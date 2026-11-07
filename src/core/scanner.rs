//! Сканування активних процесів з мережевими з'єднаннями у Windows.

use crate::core::monitor::NetworkEvent;
#[cfg(windows)]
use crate::core::zone::Zone;
#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::AF_INET;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Отримує шлях до .exe процесу за його PID.
#[cfg(windows)]
pub fn get_process_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return Some(r"C:\Windows\System32\ntoskrnl.exe".into());
    }

    unsafe {
        let handle: HANDLE = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return None,
        };

        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;

        let success = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        );

        let _ = CloseHandle(handle);

        if success.is_ok() && size > 0 {
            Some(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
pub fn get_process_path(_pid: u32) -> Option<String> {
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningSocketInfo {
    pub port: u16,
    pub protocol: String,
    pub pid: u32,
    pub process_name: String,
    pub app_path: String,
}

/// Атрибутує вхідний пакет (dropped packet), віднесений WFP до системного процесу ("System" / ntoskrnl.exe),
/// до реального процесу користувацького простору, який слухає відповідний (локальний_порт, протокол).
pub fn attribute_inbound_drop_to_listener(
    app_path: &str,
    local_port: u16,
    protocol: &str,
    listeners: &[ListeningSocketInfo],
) -> (String, u32) {
    let lower_path = app_path.to_ascii_lowercase();
    let is_system = lower_path == "system"
        || lower_path.ends_with("ntoskrnl.exe")
        || lower_path.ends_with(r"\ntoskrnl.exe");

    let matching_listener = listeners
        .iter()
        .find(|l| l.port == local_port && l.protocol.eq_ignore_ascii_case(protocol));

    if is_system {
        if let Some(l) = matching_listener {
            return (l.app_path.clone(), l.pid);
        }
    } else if let Some(l) = matching_listener {
        if l.app_path.eq_ignore_ascii_case(app_path) || lower_path.is_empty() {
            return (l.app_path.clone(), l.pid);
        }
    }

    (app_path.to_string(), 0)
}

/// Сканує всі активні сокети у стані LISTEN (TCP MIB_TCP_STATE_LISTEN та UDP).
#[cfg(windows)]
pub fn scan_listening_sockets() -> Vec<ListeningSocketInfo> {
    let mut sockets = Vec::new();
    let mut pid_path_cache: HashMap<u32, Option<String>> = HashMap::new();

    unsafe {
        // 1. TCP Listen sockets (MIB_TCP_STATE_LISTEN == 2)
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size > 0 {
            let mut buf: Vec<u8> = vec![0; size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0
            {
                let num_entries = *(buf.as_ptr() as *const u32);
                let table_ptr = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
                for i in 0..num_entries {
                    let row = &*table_ptr.add(i as usize);
                    if row.dwState == 2 {
                        let pid = row.dwOwningPid;
                        let port = u16::from_be(row.dwLocalPort as u16);
                        if port == 0 {
                            continue;
                        }

                        let path_opt = pid_path_cache
                            .entry(pid)
                            .or_insert_with(|| get_process_path(pid));
                        let app_path = path_opt.clone().unwrap_or_else(|| format!("PID:{}", pid));
                        let process_name = std::path::Path::new(&app_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown.exe")
                            .to_string();

                        sockets.push(ListeningSocketInfo {
                            port,
                            protocol: "TCP".into(),
                            pid,
                            process_name,
                            app_path,
                        });
                    }
                }
            }
        }

        // 2. UDP Listen sockets
        let mut udp_size = 0u32;
        let _ = GetExtendedUdpTable(
            None,
            &mut udp_size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if udp_size > 0 {
            let mut buf: Vec<u8> = vec![0; udp_size as usize];
            if GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut udp_size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == 0
            {
                let num_entries = *(buf.as_ptr() as *const u32);
                let table_ptr = buf.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
                for i in 0..num_entries {
                    let row = &*table_ptr.add(i as usize);
                    let pid = row.dwOwningPid;
                    let port = u16::from_be(row.dwLocalPort as u16);
                    if port == 0 {
                        continue;
                    }

                    let path_opt = pid_path_cache
                        .entry(pid)
                        .or_insert_with(|| get_process_path(pid));
                    let app_path = path_opt.clone().unwrap_or_else(|| format!("PID:{}", pid));
                    let process_name = std::path::Path::new(&app_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown.exe")
                        .to_string();

                    sockets.push(ListeningSocketInfo {
                        port,
                        protocol: "UDP".into(),
                        pid,
                        process_name,
                        app_path,
                    });
                }
            }
        }
    }

    sockets.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
    });
    sockets.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);
    sockets
}

#[cfg(not(windows))]
pub fn scan_listening_sockets() -> Vec<ListeningSocketInfo> {
    Vec::new()
}

/// Сканує поточні активні з'єднання в системі (TCP + UDP) та формує початковий список подій.
#[cfg(windows)]
pub fn scan_current_network_connections() -> Vec<NetworkEvent> {
    let mut events = Vec::new();
    let mut pid_path_cache: HashMap<u32, Option<String>> = HashMap::new();
    let process_tree = crate::core::process::get_process_tree_snapshot();
    let services_by_pid = crate::core::process::get_running_services_by_pid();

    unsafe {
        // 1. Скануємо TCP
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size > 0 {
            let mut buf: Vec<u8> = vec![0; size as usize];
            if GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0
            {
                let num_entries = *(buf.as_ptr() as *const u32);
                let table_ptr = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
                for i in 0..num_entries {
                    let row = &*table_ptr.add(i as usize);
                    let pid = row.dwOwningPid;
                    if pid == 0 {
                        continue;
                    }

                    let remote_addr_u32 = row.dwRemoteAddr;
                    if remote_addr_u32 == 0 {
                        continue;
                    }

                    let path = pid_path_cache
                        .entry(pid)
                        .or_insert_with(|| get_process_path(pid));
                    if let Some(ref app_path) = path {
                        let remote_ip = IpAddr::V4(Ipv4Addr::from(remote_addr_u32.to_be()));
                        let remote_port = u16::from_be(row.dwRemotePort as u16);

                        if remote_port == 0 || remote_ip == IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)) {
                            continue;
                        }

                        let zone = Zone::classify(&remote_ip);
                        let parent_name = process_tree.get(&pid).map(|p| p.parent_name.clone());

                        let app_name = std::path::Path::new(app_path)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("");
                        let service_name = if crate::core::process::is_shared_service_host(app_name)
                        {
                            services_by_pid.get(&pid).and_then(|svcs| {
                                let (_, svc) =
                                    crate::core::process::format_app_display_name(app_name, svcs);
                                svc
                            })
                        } else {
                            None
                        };

                        events.push(NetworkEvent {
                            timestamp: crate::core::monitor::current_timestamp_secs(),
                            app_path: app_path.clone(),
                            service_name,
                            direction: crate::core::rules::RuleDirection::Outbound,
                            process_id: pid,
                            parent_process_name: parent_name,
                            remote_ip,
                            remote_port,
                            protocol: "TCP".into(),
                            is_blocked: false,
                            zone,
                        });
                    }
                }
            }
        }

        // 2. Скануємо UDP (лише для виявлення додатків з реальною вихідною комунікацією)
        // Локальні сокети прослуховування (0.0.0.0 / 127.0.0.1) без встановленого каналу НЕ генерують спам подій виходу назовні!
    }

    events
}

#[cfg(not(windows))]
pub fn scan_current_network_connections() -> Vec<NetworkEvent> {
    Vec::new()
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

/// Декодує UTF-16LE байтовий блоб `FWP_BYTE_BLOB` (`header.appId`) у рядок NT-шляху.
pub fn decode_wfp_app_id_utf16(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let u16_len = bytes.len() / 2;
    let mut u16_buf = Vec::with_capacity(u16_len);
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for chunk in bytes.chunks_exact(2) {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]);
        if word == 0 {
            break;
        }
        u16_buf.push(word);
    }
    if u16_buf.is_empty() {
        return None;
    }
    let s = String::from_utf16_lossy(&u16_buf).trim().to_string();
    if s.is_empty() {
        None
    } else if s.eq_ignore_ascii_case("System") {
        Some(r"C:\Windows\System32\ntoskrnl.exe".into())
    } else {
        Some(s)
    }
}

/// Монітор відхилених з'єднань (Dropped TCP SYN / UDP) через Windows Filtering Platform (FwpmNetEventEnum1).
pub struct WfpDropMonitor {
    #[cfg(windows)]
    engine_handle: Option<HANDLE>,
    #[cfg(windows)]
    last_poll_filetime: u64,
    #[cfg(windows)]
    dos_device_map: HashMap<String, String>,
}

#[cfg(windows)]
fn filetime_to_u64(ft: windows::Win32::Foundation::FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

#[cfg(windows)]
fn u64_to_filetime(val: u64) -> windows::Win32::Foundation::FILETIME {
    windows::Win32::Foundation::FILETIME {
        dwLowDateTime: (val & 0xFFFF_FFFF) as u32,
        dwHighDateTime: (val >> 32) as u32,
    }
}

impl WfpDropMonitor {
    #[cfg(windows)]
    pub fn new() -> Self {
        use windows::core::PCWSTR;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmEngineOpen0, FwpmEngineSetOption0, FWPM_ENGINE_COLLECT_NET_EVENTS,
            FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWP_DATA_TYPE, FWP_VALUE0, FWP_VALUE0_0,
        };
        use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

        let dos_device_map = crate::core::interfaces::query_system_dos_device_map();
        let mut engine_handle = HANDLE::default();

        let opened = unsafe {
            // RPC_C_AUTHN_WINNT = 10
            let status = FwpmEngineOpen0(PCWSTR::null(), 10, None, None, &mut engine_handle);
            if status == 0 && !engine_handle.is_invalid() {
                // Увімкнути збір мережевих подій WFP (FWP_UINT32 = 3)
                let collect_val = FWP_VALUE0 {
                    r#type: FWP_DATA_TYPE(3),
                    Anonymous: FWP_VALUE0_0 { uint32: 1 },
                };
                let _ = FwpmEngineSetOption0(
                    engine_handle,
                    FWPM_ENGINE_COLLECT_NET_EVENTS,
                    &collect_val,
                );

                // Вмикаємо ключові слова для перехоплення всіх drop-подій
                let kw_val = FWP_VALUE0 {
                    r#type: FWP_DATA_TYPE(3),
                    Anonymous: FWP_VALUE0_0 {
                        uint32: 0xFFFF_FFFF,
                    },
                };
                let _ = FwpmEngineSetOption0(
                    engine_handle,
                    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
                    &kw_val,
                );
                Some(engine_handle)
            } else {
                None
            }
        };

        let now_ft = unsafe { GetSystemTimeAsFileTime() };
        // Беремо події за останні 15 секунд перед запуском
        let now_u64 = filetime_to_u64(now_ft);
        let start_u64 = now_u64.saturating_sub(15 * 10_000_000);

        Self {
            engine_handle: opened,
            last_poll_filetime: start_u64,
            dos_device_map,
        }
    }

    #[cfg(not(windows))]
    pub fn new() -> Self {
        Self {}
    }

    /// Зчитує всі нові відхилені вихідні спроби з'єднань (TCP SYN / UDP drops) із кільцевого буфера ядра WFP.
    #[cfg(windows)]
    pub fn poll_dropped_events(&mut self) -> Vec<NetworkEvent> {
        use std::net::Ipv6Addr;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFreeMemory0, FwpmNetEventCreateEnumHandle0, FwpmNetEventDestroyEnumHandle0,
            FwpmNetEventEnum1, FWPM_NET_EVENT1, FWPM_NET_EVENT_ENUM_TEMPLATE0,
            FWPM_NET_EVENT_TYPE_CAPABILITY_DROP, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
        };
        use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

        let Some(engine) = self.engine_handle else {
            return Vec::new();
        };

        let mut dropped_events = Vec::new();
        let mut listeners_cache: Option<Vec<ListeningSocketInfo>> = None;
        let mut services_cache: Option<HashMap<u32, Vec<crate::core::process::ServiceInfo>>> = None;
        let now_ft = unsafe { GetSystemTimeAsFileTime() };
        let now_u64 = filetime_to_u64(now_ft);
        if now_u64 <= self.last_poll_filetime {
            return dropped_events;
        }

        let template = FWPM_NET_EVENT_ENUM_TEMPLATE0 {
            startTime: u64_to_filetime(self.last_poll_filetime),
            endTime: now_ft,
            numFilterConditions: 0,
            filterCondition: std::ptr::null_mut(),
        };

        let mut max_seen_ft = self.last_poll_filetime;

        unsafe {
            let mut enum_handle = HANDLE::default();
            if FwpmNetEventCreateEnumHandle0(engine, Some(&template), &mut enum_handle) != 0 {
                return dropped_events;
            }

            let mut entries: *mut *mut FWPM_NET_EVENT1 = std::ptr::null_mut();
            let mut num_entries: u32 = 0;

            let status =
                FwpmNetEventEnum1(engine, enum_handle, 512, &mut entries, &mut num_entries);
            if status == 0 && !entries.is_null() && num_entries > 0 {
                for i in 0..num_entries {
                    let ev_ptr = *entries.add(i as usize);
                    if ev_ptr.is_null() {
                        continue;
                    }
                    let ev = &*ev_ptr;
                    let ev_ft = filetime_to_u64(ev.header.timeStamp);
                    if ev_ft > max_seen_ft {
                        max_seen_ft = ev_ft;
                    }

                    if ev.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
                        && ev.r#type != FWPM_NET_EVENT_TYPE_CAPABILITY_DROP
                    {
                        continue;
                    }

                    // Визначаємо напрямок трафіку: Outbound або Inbound
                    let mut direction = crate::core::rules::RuleDirection::Outbound;
                    if ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                        let drop_ptr = ev.Anonymous.classifyDrop;
                        if !drop_ptr.is_null() {
                            let drop_info = &*drop_ptr;
                            if drop_info.isLoopback.as_bool() {
                                continue;
                            }
                            // FWP_DIRECTION_OUTBOUND = 0, MS_FWP_DIRECTION_OUT = 0x3901 (14593)
                            // FWP_DIRECTION_INBOUND = 1, MS_FWP_DIRECTION_IN = 0x3900 (14592)
                            let dir = drop_info.msFwpDirection;
                            if dir == 0 || dir == 0x3901 {
                                direction = crate::core::rules::RuleDirection::Outbound;
                            } else if dir == 1 || dir == 0x3900 {
                                direction = crate::core::rules::RuleDirection::Inbound;
                            } else {
                                continue;
                            }
                        }
                    }

                    // Витягуємо шлях додатку з header.appId
                    let blob = ev.header.appId;
                    if blob.size == 0 || blob.data.is_null() {
                        continue;
                    }
                    let raw_bytes = std::slice::from_raw_parts(blob.data, blob.size as usize);
                    let Some(nt_path) = decode_wfp_app_id_utf16(raw_bytes) else {
                        continue;
                    };
                    let app_path = crate::core::interfaces::normalize_nt_device_path(
                        &nt_path,
                        &self.dos_device_map,
                    );

                    // Витягуємо протокол, IP та порт призначення
                    let protocol = match ev.header.ipProtocol {
                        6 => "TCP".to_string(),
                        17 => "UDP".to_string(),
                        1 | 58 => "ICMP".to_string(),
                        other => format!("IP:{}", other),
                    };

                    let remote_ip = if ev.header.ipVersion == FWP_IP_VERSION_V4 {
                        IpAddr::V4(Ipv4Addr::from(ev.header.Anonymous2.remoteAddrV4))
                    } else if ev.header.ipVersion == FWP_IP_VERSION_V6 {
                        IpAddr::V6(Ipv6Addr::from(
                            ev.header.Anonymous2.remoteAddrV6.byteArray16,
                        ))
                    } else {
                        continue;
                    };

                    let port = match direction {
                        crate::core::rules::RuleDirection::Outbound => ev.header.remotePort,
                        crate::core::rules::RuleDirection::Inbound => ev.header.localPort,
                    };

                    if remote_ip.is_unspecified()
                        || remote_ip.is_loopback()
                        || remote_ip.is_multicast()
                    {
                        continue;
                    }

                    let (final_path, final_pid) = if direction
                        == crate::core::rules::RuleDirection::Inbound
                    {
                        let listeners = listeners_cache.get_or_insert_with(scan_listening_sockets);
                        attribute_inbound_drop_to_listener(&app_path, port, &protocol, listeners)
                    } else {
                        (app_path, 0)
                    };

                    let mut service_name = None;
                    if final_pid > 0 {
                        let services = services_cache
                            .get_or_insert_with(crate::core::process::get_running_services_by_pid);
                        if let Some(svcs) = services.get(&final_pid) {
                            let app_name = std::path::Path::new(&final_path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("");
                            if crate::core::process::is_shared_service_host(app_name) {
                                let (_, svc) =
                                    crate::core::process::format_app_display_name(app_name, svcs);
                                service_name = svc;
                            }
                        }
                    }

                    let zone = Zone::classify(&remote_ip);

                    dropped_events.push(NetworkEvent {
                        timestamp: crate::core::monitor::current_timestamp_secs(),
                        app_path: final_path,
                        service_name,
                        direction,
                        process_id: final_pid,
                        parent_process_name: None,
                        remote_ip,
                        remote_port: port,
                        protocol,
                        is_blocked: true,
                        zone,
                    });
                }

                let mut raw_ptr = entries as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut raw_ptr);
            }

            let _ = FwpmNetEventDestroyEnumHandle0(engine, enum_handle);
        }

        self.last_poll_filetime = max_seen_ft.max(now_u64) + 1;
        dropped_events
    }

    #[cfg(not(windows))]
    pub fn poll_dropped_events(&mut self) -> Vec<NetworkEvent> {
        Vec::new()
    }
}

#[cfg(windows)]
impl Drop for WfpDropMonitor {
    fn drop(&mut self) {
        if let Some(engine) = self.engine_handle.take() {
            unsafe {
                let _ =
                    windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(
                        engine,
                    );
            }
        }
    }
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct MIB_UDPROW_OWNER_PID {
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_path_and_scan_connections_fallback() {
        let path = get_process_path(std::process::id());
        if cfg!(windows) {
            assert!(path.is_some());
        } else {
            assert!(path.is_none());
        }

        let conns = scan_current_network_connections();
        if !cfg!(windows) {
            assert!(conns.is_empty());
        }
    }

    #[test]
    fn test_decode_wfp_app_id_utf16_extracts_nt_path() {
        let sample = "\\device\\harddiskvolume3\\windows\\system32\\curl.exe\0";
        let utf16_bytes: Vec<u8> = sample
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        let decoded = decode_wfp_app_id_utf16(&utf16_bytes).expect("should decode UTF-16LE blob");
        assert_eq!(
            decoded,
            r"\device\harddiskvolume3\windows\system32\curl.exe"
        );
    }

    #[test]
    fn test_decode_wfp_app_id_edge_cases() {
        // Порожній або неповний зріз
        assert!(decode_wfp_app_id_utf16(&[]).is_none());
        assert!(decode_wfp_app_id_utf16(&[0x41]).is_none());

        // Тільки нуль-термінатор
        assert!(decode_wfp_app_id_utf16(&[0x00, 0x00]).is_none());

        // Системний процес "System" відображається у шлях ядра ntoskrnl.exe
        let system_bytes: Vec<u8> = "System\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(
            decode_wfp_app_id_utf16(&system_bytes),
            Some(r"C:\Windows\System32\ntoskrnl.exe".into())
        );

        // Зупинка на нуль-термінаторі (ігнорування байтів після \0)
        let mut with_trailing: Vec<u8> = "app.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        with_trailing.extend_from_slice(&[0x99, 0x99, 0x99, 0x99]);
        assert_eq!(
            decode_wfp_app_id_utf16(&with_trailing),
            Some("app.exe".into())
        );
    }

    #[test]
    fn test_scan_listening_sockets_structure() {
        let sockets = scan_listening_sockets();
        for s in &sockets {
            assert!(s.port > 0);
            assert!(s.protocol == "TCP" || s.protocol == "UDP");
            assert!(!s.process_name.is_empty());
        }
    }

    #[test]
    fn test_attribute_inbound_drop_to_listener_maps_system_to_owning_socket() {
        let listeners = vec![ListeningSocketInfo {
            port: 3000,
            protocol: "TCP".into(),
            pid: 4242,
            process_name: "node.exe".into(),
            app_path: r"C:\Program Files\nodejs\node.exe".into(),
        }];
        let (resolved_path, pid) = attribute_inbound_drop_to_listener(
            r"C:\Windows\System32\ntoskrnl.exe",
            3000,
            "TCP",
            &listeners,
        );
        assert_eq!(resolved_path, r"C:\Program Files\nodejs\node.exe");
        assert_eq!(pid, 4242);
    }

    #[test]
    fn test_attribute_inbound_drop_to_listener_unknown_port_returns_fallback() {
        let listeners = vec![ListeningSocketInfo {
            port: 80,
            protocol: "TCP".into(),
            pid: 100,
            process_name: "httpd.exe".into(),
            app_path: r"C:\Apache\httpd.exe".into(),
        }];
        let (resolved_path, pid) = attribute_inbound_drop_to_listener(
            r"C:\Windows\System32\ntoskrnl.exe",
            9999,
            "TCP",
            &listeners,
        );
        assert_eq!(resolved_path, r"C:\Windows\System32\ntoskrnl.exe");
        assert_eq!(pid, 0);

        let (non_sys_path, non_sys_pid) =
            attribute_inbound_drop_to_listener(r"C:\MyApp\app.exe", 9999, "TCP", &listeners);
        assert_eq!(non_sys_path, r"C:\MyApp\app.exe");
        assert_eq!(non_sys_pid, 0);
    }
}
