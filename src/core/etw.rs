//! Фоновий ETW-монітор мережевого трафіку (`Microsoft-Windows-Kernel-Network`).
//! Рахує вхідні (`rx_bytes`) та вихідні (`tx_bytes`) байти (TCP + UDP, IPv4 + IPv6) у розрізі `PID`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

type EtwPidMap = HashMap<u32, (u64, u64)>;

static GLOBAL_ETW_ACCUMULATOR: OnceLock<Arc<Mutex<EtwPidMap>>> = OnceLock::new();

fn global_accumulator() -> &'static Arc<Mutex<EtwPidMap>> {
    GLOBAL_ETW_ACCUMULATOR.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Парсить бінарний payload події провайдера `Microsoft-Windows-Kernel-Network`.
/// Повертає `Some((pid, rx_bytes, tx_bytes))` для подій Send/Recv/Retransmit.
pub fn parse_kernel_network_payload(
    opcode: u8,
    header_pid: u32,
    user_data: &[u8],
) -> Option<(u32, u64, u64)> {
    if user_data.len() < 8 {
        return None;
    }
    let raw_pid = u32::from_le_bytes([user_data[0], user_data[1], user_data[2], user_data[3]]);
    let size = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]) as u64;
    if size == 0 {
        return None;
    }
    let pid = if raw_pid != 0 { raw_pid } else { header_pid };
    if pid == 0 {
        return None;
    }

    // Opcodes in Microsoft-Windows-Kernel-Network:
    // 10 = IPv4 Send, 14 = IPv4 Retransmit, 26 = IPv6 Send, 30 = IPv6 Retransmit
    // 11 = IPv4 Recv, 27 = IPv6 Recv
    match opcode {
        10 | 14 | 26 | 30 => Some((pid, 0, size)),
        11 | 27 => Some((pid, size, 0)),
        _ => None,
    }
}

pub struct EtwNetworkMonitor {
    accumulator: Arc<Mutex<HashMap<u32, (u64, u64)>>>,
}

impl Default for EtwNetworkMonitor {
    fn default() -> Self {
        Self::start()
    }
}

impl EtwNetworkMonitor {
    pub fn start() -> Self {
        let accumulator = Arc::clone(global_accumulator());
        #[cfg(windows)]
        {
            if !cfg!(test) {
                std::thread::spawn(|| {
                    run_etw_trace_thread();
                });
            }
        }
        Self { accumulator }
    }

    /// Атомарно забирає накопичені дельти `(rx_bytes, tx_bytes)` по кожному `PID` з моменту попереднього виклику.
    pub fn drain_pid_deltas(&self) -> HashMap<u32, (u64, u64)> {
        if let Ok(mut guard) = self.accumulator.lock() {
            std::mem::take(&mut *guard)
        } else {
            HashMap::new()
        }
    }

    pub fn record_sample_for_test(&self, pid: u32, rx: u64, tx: u64) {
        if let Ok(mut guard) = self.accumulator.lock() {
            let entry = guard.entry(pid).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(rx);
            entry.1 = entry.1.saturating_add(tx);
        }
    }

    /// Зупиняє ETW-сесію в ядрі Windows (викликається при виході та в panic hook).
    pub fn stop_session() {
        #[cfg(windows)]
        {
            if !cfg!(test) {
                stop_etw_session_internal();
            }
        }
    }
}

impl Drop for EtwNetworkMonitor {
    fn drop(&mut self) {
        Self::stop_session();
    }
}

#[cfg(windows)]
const SESSION_NAME: windows::core::PCWSTR = windows::core::w!("itsfw-etw-net-monitor");

#[cfg(windows)]
const KERNEL_NETWORK_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

#[cfg(windows)]
fn alloc_trace_properties_buf() -> Vec<u8> {
    use windows::Win32::System::Diagnostics::Etw::{
        EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, WNODE_FLAG_TRACED_GUID,
    };
    let session_bytes = 64usize;
    let total_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + session_bytes;
    let mut buf = vec![0u8; total_size];
    unsafe {
        let props = &mut *(buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
        props.Wnode.BufferSize = total_size as u32;
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = 1;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buf
}

#[cfg(windows)]
fn stop_etw_session_internal() {
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };
    let mut buf = alloc_trace_properties_buf();
    unsafe {
        let props_ptr = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            SESSION_NAME,
            props_ptr,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

#[cfg(windows)]
unsafe extern "system" fn etw_event_record_callback(
    event_record: *mut windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    if record.event_header_provider_is_kernel_network() {
        let user_len = record.UserDataLength as usize;
        if record.UserData.is_null() || user_len < 8 {
            return;
        }
        let slice = std::slice::from_raw_parts(record.UserData as *const u8, user_len);
        let opcode = record.EventHeader.EventDescriptor.Opcode;
        let header_pid = record.EventHeader.ProcessId;
        if let Some((pid, rx, tx)) = parse_kernel_network_payload(opcode, header_pid, slice) {
            if let Ok(mut guard) = global_accumulator().lock() {
                let entry = guard.entry(pid).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(rx);
                entry.1 = entry.1.saturating_add(tx);
            }
        }
    }
}

#[cfg(windows)]
trait EventRecordExt {
    fn event_header_provider_is_kernel_network(&self) -> bool;
}

#[cfg(windows)]
impl EventRecordExt for windows::Win32::System::Diagnostics::Etw::EVENT_RECORD {
    #[inline]
    fn event_header_provider_is_kernel_network(&self) -> bool {
        self.EventHeader.ProviderId == KERNEL_NETWORK_GUID
    }
}

#[cfg(windows)]
fn run_etw_trace_thread() {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Diagnostics::Etw::{
        CloseTrace, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
        PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    };

    stop_etw_session_internal();

    let mut prop_buf = alloc_trace_properties_buf();
    let mut session_handle = CONTROLTRACE_HANDLE::default();
    unsafe {
        let props_ptr = prop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let start_err = StartTraceW(&mut session_handle, SESSION_NAME, props_ptr);
        if start_err != ERROR_SUCCESS {
            return;
        }

        let enable_err = EnableTraceEx2(
            session_handle,
            &KERNEL_NETWORK_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            4, // TRACE_LEVEL_INFORMATION
            0x30,
            0,
            0,
            None,
        );
        if enable_err != ERROR_SUCCESS {
            stop_etw_session_internal();
            return;
        }

        let mut session_name_utf16: Vec<u16> = "itsfw-etw-net-monitor\0".encode_utf16().collect();
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name_utf16.as_mut_ptr()),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX || trace_handle.Value == 0 {
            stop_etw_session_internal();
            return;
        }

        let _ = ProcessTrace(&[trace_handle], None, None);
        let _ = CloseTrace(trace_handle);
        stop_etw_session_internal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_network_payload_send_recv_and_edge_cases() {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&4242u32.to_le_bytes());
        buf[4..8].copy_from_slice(&1500u32.to_le_bytes());

        // IPv4 Send (opcode 10) -> tx = 1500
        assert_eq!(
            parse_kernel_network_payload(10, 100, &buf),
            Some((4242, 0, 1500))
        );
        // IPv6 Receive (opcode 27) -> rx = 1500
        assert_eq!(
            parse_kernel_network_payload(27, 100, &buf),
            Some((4242, 1500, 0))
        );
        // Fallback to header_pid when payload pid == 0
        let mut zero_pid_buf = buf;
        zero_pid_buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_kernel_network_payload(11, 777, &zero_pid_buf),
            Some((777, 1500, 0))
        );
        // Both PIDs 0 -> None
        assert_eq!(parse_kernel_network_payload(11, 0, &zero_pid_buf), None);
        // Short buffer -> None
        assert_eq!(parse_kernel_network_payload(10, 100, &[1, 2, 3]), None);
        // Unknown opcode -> None
        assert_eq!(parse_kernel_network_payload(99, 100, &buf), None);
    }

    #[test]
    fn test_etw_monitor_drain_deltas() {
        let mon = EtwNetworkMonitor::start();
        let _ = mon.drain_pid_deltas();
        mon.record_sample_for_test(1234, 1024, 2048);
        mon.record_sample_for_test(1234, 512, 512);
        let deltas = mon.drain_pid_deltas();
        assert_eq!(deltas.get(&1234), Some(&(1536, 2560)));
        assert!(mon.drain_pid_deltas().is_empty());
    }
}
