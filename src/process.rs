//! Process helpers: name / path / creation time / is it system-critical / enable SeDebugPrivilege.

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{PCWSTR, PWSTR, s, w};

/// Ordinary processes that must not be ended: explorer often holds files open for its thumbnail cache,
/// and ending it in bulk takes the desktop and taskbar down with it.
/// System-critical processes are blocked separately by [`is_critical_process`].
pub const KILL_PROTECTED: &[&str] = &["explorer.exe"];

/// System-critical process names (lowercase). Ending any of them blue-screens Windows (CRITICAL_PROCESS_DIED).
const CRITICAL_NAMES: &[&str] = &[
    "system", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
];

/// System-critical process: never close its handles or end it; such locks can only be cleared by
/// deleting on reboot. PID ≤ 4 / on the critical-name list / has the ProcessBreakOnTermination flag → yes.
/// If the flag can't be read, decide by name; if the name can't be read either, treat it as critical
/// (better to leave it alone).
pub fn is_critical_process(pid: u32) -> bool {
    type NtQipFn = unsafe extern "system" fn(HANDLE, u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
    const PROCESS_BREAK_ON_TERMINATION: u32 = 29;

    if pid <= 4 {
        return true;
    }
    let name = process_basename(pid).map(|n| n.to_ascii_lowercase());
    if name.as_deref().is_some_and(|n| CRITICAL_NAMES.contains(&n)) {
        return true;
    }
    let flag = unsafe {
        use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
        let f = GetModuleHandleW(w!("ntdll.dll")).ok().and_then(|m| GetProcAddress(m, s!("NtQueryInformationProcess")));
        match (f, OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)) {
            (Some(f), Ok(h)) => {
                let f: NtQipFn = std::mem::transmute(f);
                let mut v: u32 = 0;
                let st = f(h, PROCESS_BREAK_ON_TERMINATION, &mut v as *mut u32 as *mut _, 4, std::ptr::null_mut());
                let _ = CloseHandle(h);
                (st >= 0).then_some(v != 0)
            }
            (_, Ok(h)) => {
                let _ = CloseHandle(h);
                None
            }
            _ => None,
        }
    };
    match flag {
        Some(critical) => critical,
        None => name.is_none(),
    }
}

pub fn enable_se_debug_privilege() {
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    };
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token).is_err() {
            return;
        }
        let mut luid = Default::default();
        if LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid).is_ok() {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            let _ = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        }
        let _ = CloseHandle(token);
    }
}

/// Full path of the process exe (limited query access is enough, so most processes work without elevation).
pub fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut result = None;
        for cap in [1024usize, 32767] {
            let mut buf = vec![0u16; cap];
            let mut len = buf.len() as u32;
            if QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
                result = Some(String::from_utf16_lossy(&buf[..len as usize]));
                break;
            }
        }
        let _ = CloseHandle(h);
        result
    }
}

pub fn process_basename(pid: u32) -> Option<String> {
    let full = process_image_path(pid)?;
    Path::new(&full).file_name().map(|n| n.to_string_lossy().into_owned())
}

/// Process creation time (64-bit FILETIME). Re-checked before acting, so a reused PID isn't hit by mistake.
pub fn process_start_time(pid: u32) -> Option<u64> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let t = process_start_time_of(h);
        let _ = CloseHandle(h);
        t
    }
}

pub fn process_start_time_of(h: HANDLE) -> Option<u64> {
    unsafe {
        let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).ok()?;
        Some(((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_pids_are_critical() {
        assert!(is_critical_process(0));
        assert!(is_critical_process(4), "touching System means a blue screen");
        let me = std::process::id();
        assert!(!is_critical_process(me), "this (ordinary) process is not critical");
    }

    #[test]
    fn explorer_is_protected() {
        assert!(KILL_PROTECTED.contains(&"explorer.exe"));
    }
}
