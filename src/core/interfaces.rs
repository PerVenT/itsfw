use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub description: String,
    pub index: u32,
    pub is_up: bool,
}

/// Перетворює NT-шлях пристрою формату `\Device\HarddiskVolumeX\path\file.exe` (або нижнього регістру з WFP) у звичний `C:\path\file.exe`.
pub fn normalize_nt_device_path(nt_path: &str, device_map: &HashMap<String, String>) -> String {
    let nt_lower = nt_path.to_lowercase();
    // Сортуємо ключі за спаданням довжини, щоб \Device\HarddiskVolume10 не збігся з \Device\HarddiskVolume1
    let mut entries: Vec<(&String, &String)> = device_map.iter().collect();
    entries.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

    for (device_prefix, drive_letter) in entries {
        let prefix_lower = device_prefix.to_lowercase();
        if nt_lower.starts_with(&prefix_lower) {
            let rest = &nt_path[device_prefix.len()..];
            if rest.is_empty() || rest.starts_with('\\') || rest.starts_with('/') {
                let clean_relative = rest.trim_start_matches(['\\', '/']);
                return format!("{}:\\{}", drive_letter, clean_relative);
            }
        }
    }
    nt_path.to_string()
}

/// Отримує актуальний мапінг томів на Windows (`\Device\HarddiskVolumeX` -> `C`)
#[cfg(windows)]
pub fn query_system_dos_device_map() -> HashMap<String, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};

    let mut map = HashMap::new();
    let mut buffer = [0u16; 512];

    unsafe {
        let len = GetLogicalDriveStringsW(Some(&mut buffer));
        if len == 0 || len > buffer.len() as u32 {
            return map;
        }

        let slice = &buffer[..len as usize];
        for drive_chars in slice.split(|&c| c == 0) {
            if drive_chars.is_empty() {
                continue;
            }

            let drive_os = OsString::from_wide(drive_chars);
            let drive_str = drive_os.to_string_lossy();
            let drive_letter = drive_str
                .trim_end_matches(['\\', '/'])
                .trim_end_matches(':');

            let device_name = format!("{}:", drive_letter);
            let mut device_name_w: Vec<u16> = device_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut target_buf = [0u16; 512];
            let target_len =
                QueryDosDeviceW(PCWSTR(device_name_w.as_mut_ptr()), Some(&mut target_buf));

            if target_len > 0 {
                let target_os = OsString::from_wide(&target_buf[..target_len as usize - 2]);
                let target_str = target_os.to_string_lossy().to_string();
                map.insert(target_str, drive_letter.to_uppercase());
            }
        }
    }

    map
}

#[cfg(not(windows))]
pub fn query_system_dos_device_map() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_nt_device_path_equivalence_partitions() {
        let mut map = HashMap::new();
        map.insert(r"\Device\HarddiskVolume1".into(), "C".into());
        map.insert(r"\Device\HarddiskVolume2".into(), "D".into());

        // 1. Клас еквівалентності: Відомий том із прямим збігом регістру
        let standard_path = r"\Device\HarddiskVolume1\Windows\System32\cmd.exe";
        assert_eq!(
            normalize_nt_device_path(standard_path, &map),
            r"C:\Windows\System32\cmd.exe"
        );

        let secondary_drive_path = r"\Device\HarddiskVolume2\Data\app.exe";
        assert_eq!(
            normalize_nt_device_path(secondary_drive_path, &map),
            r"D:\Data\app.exe"
        );

        // 2. Клас еквівалентності: Невідомий том повертається без змін
        let unknown_volume_path = r"\Device\UnknownVolume\app.exe";
        assert_eq!(
            normalize_nt_device_path(unknown_volume_path, &map),
            unknown_volume_path
        );

        // 3. Клас еквівалентності: Незалежність від регістру префікса (WFP lowercase paths)
        let lowercase_prefix_path = r"\device\harddiskvolume1\program files\app\binary.exe";
        assert_eq!(
            normalize_nt_device_path(lowercase_prefix_path, &map),
            r"C:\program files\app\binary.exe"
        );

        // 4. Граничне значення: корінь тома без підкаталогів
        let root_only_path = r"\Device\HarddiskVolume1\";
        assert_eq!(normalize_nt_device_path(root_only_path, &map), r"C:\");
    }

    #[test]
    fn test_network_interface_info_and_dos_device_query() {
        let iface = NetworkInterfaceInfo {
            name: "Ethernet".into(),
            description: "Gigabit Adapter".into(),
            index: 12,
            is_up: true,
        };
        assert_eq!(iface.index, 12);
        assert!(iface.is_up);

        let map = query_system_dos_device_map();
        if cfg!(windows) {
            // On Windows, system drive C is typically present
            assert!(!map.is_empty());
        } else {
            // Safe fallback on non-Windows
            assert!(map.is_empty());
        }
    }
}
