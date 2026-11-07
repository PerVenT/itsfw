//! Отримання інформації про дерево процесів (Parent PID та ім'я батьківського процесу) у Windows.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessParentInfo {
    pub parent_pid: u32,
    pub parent_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub service_name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Verified(String),
    Unsigned,
    Untrusted,
    Unknown,
}

impl SignatureStatus {
    pub fn badge(&self) -> &'static str {
        match self {
            SignatureStatus::Verified(_) => "✓ Signed (Verified)",
            SignatureStatus::Unsigned => "⚠ Unsigned",
            SignatureStatus::Untrusted => "✗ Untrusted Signature",
            SignatureStatus::Unknown => "? Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMetadata {
    pub description: Option<String>,
    pub signature: SignatureStatus,
    pub is_suspicious_path: bool,
}

pub fn is_shared_service_host(exe_name: &str) -> bool {
    let filename = exe_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(exe_name);
    matches!(
        filename.to_ascii_lowercase().as_str(),
        "svchost.exe"
            | "tcpsvcs.exe"
            | "lms.exe"
            | "ntoskrnl.exe"
            | "dllhost.exe"
            | "taskhostw.exe"
            | "wmiprvse.exe"
    )
}

pub fn format_app_display_name(
    app_name: &str,
    services: &[ServiceInfo],
) -> (String, Option<String>) {
    if is_shared_service_host(app_name) && !services.is_empty() {
        let primary = &services[0].service_name;
        let label = if services.len() == 1 {
            format!("{app_name} [{primary}]")
        } else {
            format!("{app_name} [{primary} +{}]", services.len() - 1)
        };
        (label, Some(primary.clone()))
    } else {
        (app_name.to_string(), None)
    }
}

pub fn is_suspicious_exec_path(path: &str) -> bool {
    let normalized = path.replace('/', "\\").to_ascii_lowercase();
    normalized.contains(r"\appdata\local\temp\")
        || normalized.contains(r"\appdata\roaming\")
        || normalized.contains(r"\downloads\")
        || normalized.contains(r"\public\")
        || normalized.contains(r"\perflogs\")
}

pub fn build_parent_map(
    pid_to_parent: &HashMap<u32, u32>,
    pid_to_name: &HashMap<u32, String>,
) -> HashMap<u32, ProcessParentInfo> {
    let mut map = HashMap::new();
    for (&pid, &parent_pid) in pid_to_parent {
        let parent_name = pid_to_name
            .get(&parent_pid)
            .cloned()
            .unwrap_or_else(|| "Unknown".into());
        map.insert(
            pid,
            ProcessParentInfo {
                parent_pid,
                parent_name,
            },
        );
    }
    map
}

#[cfg(windows)]
pub fn get_process_tree_snapshot() -> HashMap<u32, ProcessParentInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut pid_to_name: HashMap<u32, String> = HashMap::new();
    let mut pid_to_parent: HashMap<u32, u32> = HashMap::new();

    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return HashMap::new(),
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                let parent_pid = entry.th32ParentProcessID;

                // Читаємо szExeFile
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                pid_to_name.insert(pid, exe_name);
                pid_to_parent.insert(pid, parent_pid);

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    build_parent_map(&pid_to_parent, &pid_to_name)
}

#[cfg(not(windows))]
pub fn get_process_tree_snapshot() -> HashMap<u32, ProcessParentInfo> {
    HashMap::new()
}

#[cfg(windows)]
pub fn get_running_services_by_pid() -> HashMap<u32, Vec<ServiceInfo>> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
        SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
    };

    let mut map: HashMap<u32, Vec<ServiceInfo>> = HashMap::new();

    unsafe {
        let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(h) => h,
            Err(_) => return map,
        };

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        let res = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            PCWSTR::null(),
        );

        if res.is_err() && bytes_needed > 0 {
            let mut buffer = vec![0u8; bytes_needed as usize];
            resume_handle = 0;
            let success = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                Some(&mut buffer),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            );

            if success.is_ok() && services_returned > 0 {
                let status_ptr = buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
                for i in 0..services_returned as usize {
                    let item = &*status_ptr.add(i);
                    let pid = item.ServiceStatusProcess.dwProcessId;
                    if pid != 0 {
                        let service_name = item.lpServiceName.to_string().unwrap_or_default();
                        let display_name = item.lpDisplayName.to_string().unwrap_or_default();
                        map.entry(pid).or_default().push(ServiceInfo {
                            service_name,
                            display_name,
                        });
                    }
                }
            }
        }

        let _ = CloseServiceHandle(scm);
    }

    map
}

#[cfg(not(windows))]
pub fn get_running_services_by_pid() -> HashMap<u32, Vec<ServiceInfo>> {
    HashMap::new()
}

#[cfg(windows)]
pub fn query_process_metadata(app_path: &str) -> ProcessMetadata {
    let is_suspicious_path = is_suspicious_exec_path(app_path);
    if !std::path::Path::new(app_path).is_file() {
        return ProcessMetadata {
            description: None,
            signature: SignatureStatus::Unknown,
            is_suspicious_path,
        };
    }

    let description = query_file_description(app_path);
    let signature = verify_authenticode_signature(app_path);

    ProcessMetadata {
        description,
        signature,
        is_suspicious_path,
    }
}

#[cfg(not(windows))]
pub fn query_process_metadata(app_path: &str) -> ProcessMetadata {
    ProcessMetadata {
        description: None,
        signature: SignatureStatus::Unknown,
        is_suspicious_path: is_suspicious_exec_path(app_path),
    }
}

#[cfg(windows)]
fn query_file_description(app_path: &str) -> Option<String> {
    use std::ffi::c_void;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
    };

    let wide_path = HSTRING::from(app_path);
    let mut dummy = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(&wide_path, Some(&mut dummy)) };
    if size == 0 {
        return None;
    }

    let mut data = vec![0u8; size as usize];
    let ok = unsafe {
        GetFileVersionInfoW(&wide_path, 0, size, data.as_mut_ptr() as *mut c_void)
    };
    if ok.is_err() {
        return None;
    }

    // Try reading \VarFileInfo\Translation first
    let mut trans_ptr: *mut c_void = std::ptr::null_mut();
    let mut trans_len: u32 = 0;
    let trans_subblock = windows::core::w!("\\VarFileInfo\\Translation");
    let has_trans = unsafe {
        VerQueryValueW(
            data.as_ptr() as *const c_void,
            trans_subblock,
            &mut trans_ptr,
            &mut trans_len,
        )
    }.as_bool();

    let mut subblocks_to_try = Vec::new();
    if has_trans && !trans_ptr.is_null() && trans_len >= 4 {
        let trans_slice = unsafe {
            std::slice::from_raw_parts(trans_ptr as *const u16, (trans_len / 2) as usize)
        };
        let lang = trans_slice[0];
        let codepage = trans_slice[1];
        subblocks_to_try.push(format!("\\StringFileInfo\\{:04x}{:04x}\\FileDescription", lang, codepage));
    }

    // Fallbacks per Spec §3.4
    subblocks_to_try.push("\\StringFileInfo\\040904B0\\FileDescription".into());
    subblocks_to_try.push("\\StringFileInfo\\040904E4\\FileDescription".into());

    for subblock in subblocks_to_try {
        let h_subblock = HSTRING::from(subblock);
        let mut desc_ptr: *mut c_void = std::ptr::null_mut();
        let mut desc_len: u32 = 0;
        let success = unsafe {
            VerQueryValueW(
                data.as_ptr() as *const c_void,
                PCWSTR(h_subblock.as_ptr()),
                &mut desc_ptr,
                &mut desc_len,
            )
        }.as_bool();

        if success && !desc_ptr.is_null() && desc_len > 0 {
            let u16_slice = unsafe {
                std::slice::from_raw_parts(desc_ptr as *const u16, desc_len as usize)
            };
            let text = String::from_utf16_lossy(u16_slice)
                .trim_matches('\0')
                .trim()
                .to_string();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }

    None
}

#[cfg(windows)]
fn verify_authenticode_signature(app_path: &str) -> SignatureStatus {
    use std::ffi::c_void;
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
        WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide_path = HSTRING::from(app_path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide_path.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: Default::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: Default::default(),
        dwUIContext: Default::default(),
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let res = unsafe {
        WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut c_void,
        )
    };

    // Close action per Spec §3.4
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND(std::ptr::null_mut()),
            &mut action_guid,
            &mut trust_data as *mut _ as *mut c_void,
        );
    }

    const TRUST_E_NOSIGNATURE: i32 = 0x800B0100u32 as i32;

    if res == 0 {
        SignatureStatus::Verified("Authenticode".into())
    } else if res == TRUST_E_NOSIGNATURE {
        SignatureStatus::Unsigned
    } else {
        SignatureStatus::Untrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_parent_info_struct() {
        let info = ProcessParentInfo {
            parent_pid: 1234,
            parent_name: "cmd.exe".into(),
        };
        assert_eq!(info.parent_pid, 1234);
        assert_eq!(info.parent_name, "cmd.exe");
    }

    #[test]
    fn test_build_parent_map_resolves_known_and_unknown_parents() {
        let mut pid_to_parent = HashMap::new();
        let mut pid_to_name = HashMap::new();

        // 1. Process with known parent
        pid_to_name.insert(100, "explorer.exe".into());
        pid_to_name.insert(200, "chrome.exe".into());
        pid_to_parent.insert(200, 100);

        // 2. Process whose parent is terminated / missing from snapshot
        pid_to_name.insert(300, "orphan.exe".into());
        pid_to_parent.insert(300, 999);

        // 3. Root / System idle process
        pid_to_name.insert(0, "System Idle Process".into());
        pid_to_parent.insert(0, 0);

        let map = build_parent_map(&pid_to_parent, &pid_to_name);

        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get(&200),
            Some(&ProcessParentInfo {
                parent_pid: 100,
                parent_name: "explorer.exe".into()
            })
        );
        assert_eq!(
            map.get(&300),
            Some(&ProcessParentInfo {
                parent_pid: 999,
                parent_name: "Unknown".into()
            })
        );
        assert_eq!(
            map.get(&0),
            Some(&ProcessParentInfo {
                parent_pid: 0,
                parent_name: "System Idle Process".into()
            })
        );
    }

    #[test]
    fn test_get_process_tree_snapshot_returns_map_or_empty_on_linux() {
        let snapshot = get_process_tree_snapshot();
        // On Linux/Podman it safely returns an empty map, on Windows it returns running processes
        if cfg!(windows) {
            assert!(!snapshot.is_empty());
        } else {
            assert!(snapshot.is_empty());
        }
    }

    #[test]
    fn test_shared_service_host_detection_and_disambiguation() {
        assert!(is_shared_service_host("svchost.exe"));
        assert!(is_shared_service_host("SVCHOST.EXE"));
        assert!(is_shared_service_host("tcpsvcs.exe"));
        assert!(is_shared_service_host("LMS.exe"));
        assert!(is_shared_service_host("ntoskrnl.exe"));
        assert!(!is_shared_service_host("chrome.exe"));

        let svcs = vec![ServiceInfo {
            service_name: "Dnscache".into(),
            display_name: "DNS Client".into(),
        }];
        let (label, primary_svc) = format_app_display_name("svchost.exe", &svcs);
        assert_eq!(label, "svchost.exe [Dnscache]");
        assert_eq!(primary_svc, Some("Dnscache".into()));

        let multi_svcs = vec![
            ServiceInfo { service_name: "wuauserv".into(), display_name: "Windows Update".into() },
            ServiceInfo { service_name: "bits".into(), display_name: "BITS".into() },
        ];
        let (multi_label, multi_primary) = format_app_display_name("svchost.exe", &multi_svcs);
        assert_eq!(multi_label, "svchost.exe [wuauserv +1]");
        assert_eq!(multi_primary, Some("wuauserv".into()));

        let (normal_label, normal_svc) = format_app_display_name("firefox.exe", &svcs);
        assert_eq!(normal_label, "firefox.exe");
        assert_eq!(normal_svc, None);
    }

    #[test]
    fn test_suspicious_path_and_signature_badges() {
        assert!(is_suspicious_exec_path(r"C:\Users\Admin\AppData\Local\Temp\dropper.exe"));
        assert!(is_suspicious_exec_path(r"C:\Users\Admin\Downloads\installer.exe"));
        assert!(!is_suspicious_exec_path(r"C:\Program Files\Git\bin\git.exe"));
        assert!(!is_suspicious_exec_path(r"C:\Windows\System32\svchost.exe"));

        assert_eq!(SignatureStatus::Verified("Microsoft".into()).badge(), "✓ Signed (Verified)");
        assert_eq!(SignatureStatus::Unsigned.badge(), "⚠ Unsigned");
        assert_eq!(SignatureStatus::Untrusted.badge(), "✗ Untrusted Signature");
        assert_eq!(SignatureStatus::Unknown.badge(), "? Unknown");
    }

    #[test]
    fn test_query_process_metadata_on_linux_and_running_services() {
        let meta = query_process_metadata(r"C:\Users\Admin\AppData\Local\Temp\evil.exe");
        assert!(meta.is_suspicious_path);
        assert_eq!(meta.signature, SignatureStatus::Unknown);
        assert_eq!(meta.description, None);

        let services_by_pid = get_running_services_by_pid();
        if cfg!(not(windows)) {
            assert!(services_by_pid.is_empty());
        }
    }
}
