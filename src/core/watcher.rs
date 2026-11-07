//! Background Windows Firewall Registry Watcher using `RegNotifyChangeKeyValue`.
//!
//! Monitors `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
//! to detect external firewall rule changes with zero continuous CPU usage.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_channel::Receiver;
#[cfg(windows)]
use crossbeam_channel::Sender;

pub const DEBOUNCE_DURATION: Duration = Duration::from_millis(400);
pub const SELF_MUTATION_SUPPRESSION_MS: u64 = 800;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallWatchEvent {
    ExternalChangeDetected,
}

/// Returns true if the event occurred within `window_ms` after `last_self_mutation_ms`.
pub fn should_suppress_event(last_self_mutation_ms: u64, now_ms: u64, window_ms: u64) -> bool {
    last_self_mutation_ms > 0
        && now_ms >= last_self_mutation_ms
        && (now_ms - last_self_mutation_ms) <= window_ms
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct FirewallRegistryWatcher {
    last_self_mutation_ms: Arc<AtomicU64>,
    receiver: Receiver<FirewallWatchEvent>,
}

impl FirewallRegistryWatcher {
    pub fn start() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let last_self_mutation_ms = Arc::new(AtomicU64::new(0));

        #[cfg(windows)]
        {
            let last_ms = Arc::clone(&last_self_mutation_ms);
            std::thread::Builder::new()
                .name("firewall-reg-watcher".into())
                .spawn(move || {
                    run_watcher_loop(tx, last_ms);
                })
                .ok();
        }
        #[cfg(not(windows))]
        {
            let _ = tx;
        }

        Self {
            last_self_mutation_ms,
            receiver: rx,
        }
    }

    pub fn mark_self_mutation(&self) {
        self.last_self_mutation_ms
            .store(current_time_ms(), Ordering::SeqCst);
    }

    pub fn is_in_suppression_window(&self) -> bool {
        let last = self.last_self_mutation_ms.load(Ordering::SeqCst);
        should_suppress_event(last, current_time_ms(), SELF_MUTATION_SUPPRESSION_MS)
    }

    pub fn try_recv(&self) -> Option<FirewallWatchEvent> {
        self.receiver.try_recv().ok()
    }
}

#[cfg(windows)]
fn run_watcher_loop(tx: Sender<FirewallWatchEvent>, last_self_mutation_ms: Arc<AtomicU64>) {
    use windows::core::w;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY,
        REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    };

    let mut hkey = HKEY::default();
    let subkey =
        w!("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy");

    let open_res = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_NOTIFY, &mut hkey) };

    if open_res.is_err() {
        return;
    }

    loop {
        let notify_res = unsafe {
            RegNotifyChangeKeyValue(
                hkey,
                true,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                HANDLE::default(),
                false,
            )
        };

        if notify_res.is_err() {
            break;
        }

        // Debounce window to coalesce burst writes
        std::thread::sleep(DEBOUNCE_DURATION);

        let now = current_time_ms();
        let last = last_self_mutation_ms.load(Ordering::SeqCst);

        if !should_suppress_event(last, now, SELF_MUTATION_SUPPRESSION_MS)
            && tx.send(FirewallWatchEvent::ExternalChangeDetected).is_err()
        {
            // Receiver was dropped, exit thread
            break;
        }
    }

    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_mutation_suppression_window() {
        assert!(!should_suppress_event(0, 5000, 800));
        assert!(should_suppress_event(5000, 5400, 800));
        assert!(should_suppress_event(5000, 5800, 800));
        assert!(!should_suppress_event(5000, 5801, 800));
        assert!(!should_suppress_event(5000, 4999, 800));
    }

    #[test]
    fn test_watcher_mark_self_mutation_and_channel() {
        let watcher = FirewallRegistryWatcher::start();
        assert!(!watcher.is_in_suppression_window());
        watcher.mark_self_mutation();
        assert!(watcher.is_in_suppression_window());
        assert!(watcher.try_recv().is_none());
    }

    #[test]
    fn test_watcher_clone_and_event_eq() {
        let watcher = FirewallRegistryWatcher::start();
        let cloned = watcher.clone();
        watcher.mark_self_mutation();
        assert!(cloned.is_in_suppression_window());
        assert_eq!(
            FirewallWatchEvent::ExternalChangeDetected,
            FirewallWatchEvent::ExternalChangeDetected
        );
    }
}
