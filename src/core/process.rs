//! Отримання інформації про дерево процесів (Parent PID та ім'я батьківського процесу) у Windows.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessParentInfo {
    pub parent_pid: u32,
    pub parent_name: String,
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
}
