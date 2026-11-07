//! Перевірка наявності адміністративних привілеїв у Windows.

#[cfg(windows)]
use windows::core::BOOL;
#[cfg(windows)]
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, PSID,
    WELL_KNOWN_SID_TYPE,
};

/// Перевіряє, чи поточний процес запущено з правами локального адміністратора.
pub fn is_running_as_admin() -> bool {
    #[cfg(windows)]
    unsafe {
        let mut admin_sid: [u8; 64] = [0; 64];
        let mut sid_size = admin_sid.len() as u32;

        let created = CreateWellKnownSid(
            WELL_KNOWN_SID_TYPE(WinBuiltinAdministratorsSid.0),
            None,
            Some(PSID(admin_sid.as_mut_ptr() as *mut _)),
            &mut sid_size,
        );

        if !created.is_ok() {
            return false;
        }

        let mut is_member = BOOL(0);
        let check_res =
            CheckTokenMembership(None, PSID(admin_sid.as_mut_ptr() as *mut _), &mut is_member);

        check_res.is_ok() && is_member.as_bool()
    }

    #[cfg(not(windows))]
    {
        // Для компіляції під час крос-перевірки або не-Windows платформ
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_running_as_admin_does_not_panic() {
        // Тест повинен повертати булеве значення без паніки
        let _res = is_running_as_admin();
    }
}
