//! Force delete (used after unlocking) + delete on reboot. No Recycle Bin and no shell progress dialog:
//! engine only, the caller handles any messages.
//!
//! - Directory tree: enumerate first → delete files in parallel → delete directories level by level from
//!   the deepest up, each level in parallel (≤ 8 threads, idea taken from rmx)
//! - Each entry is first deleted with POSIX semantics (with FORCE_IMAGE_SECTION_CHECK, so even a running
//!   exe / loaded DLL has its name removed; read-only is ignored too), otherwise clear read-only and fall
//!   back to std; short-lived locks from antivirus / the indexer are retried with backoff
//! - Errors don't stop the run: everything deletable is deleted, leaving only the undeletable files and
//!   the directory chain they live in
//! - `\\?\` prefix to get past MAX_PATH; junctions / symlinks are removed as links and never entered
//! - Dangerous paths (drive roots / Windows / Program Files / the user profile folder itself) are refused

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Delete counts.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeleteStats {
    pub files: u64,
    pub dirs: u64,
}

#[derive(Debug)]
pub enum DeleteError {
    NotFound,
    /// Refused: the target is a dangerous path.
    Protected,
    /// Something couldn't be deleted: the first failing path + the system error text.
    Io { path: String, err: String },
}

/// Argument for the elevated delete-on-reboot helper: `<exe> --delete-on-reboot <list file>`. The host
/// handles it by calling [`run_reboot_delete_helper`] at the very top of main (before any single-instance check).
pub const REBOOT_DELETE_ARG: &str = "--delete-on-reboot";

/// Force-deletes `target` (an absolute path).
pub fn force_delete(target: &Path) -> Result<DeleteStats, DeleteError> {
    // symlink_metadata doesn't follow links: if the target is a junction, delete only the link, not what it points to
    let md = std::fs::symlink_metadata(target).map_err(|_| DeleteError::NotFound)?;
    if is_protected_path(target) {
        return Err(DeleteError::Protected);
    }
    let mut stats = DeleteStats::default();
    let long = to_long_path(target);
    let ft = md.file_type();
    if ft.is_dir() && !ft.is_symlink() {
        delete_tree(&long, &mut stats)?;
    } else {
        delete_entry(&long, ft.is_dir())?;
        stats.files += 1;
    }
    Ok(stats)
}

fn delete_tree(root: &Path, stats: &mut DeleteStats) -> Result<(), DeleteError> {
    let mut leaves: Vec<(PathBuf, bool)> = Vec::new(); // (path, is a directory link)
    let mut dirs: Vec<(usize, PathBuf)> = Vec::new(); // (depth, path)
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut first_err = None;
    while let Some((dir, depth)) = stack.pop() {
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let child = e.path();
                    match e.file_type() {
                        Ok(ft) if ft.is_symlink() => leaves.push((child, ft.is_dir())),
                        Ok(ft) if ft.is_dir() => stack.push((child, depth + 1)),
                        Ok(_) => leaves.push((child, false)),
                        Err(err) => {
                            first_err.get_or_insert(io_err(&child, err));
                        }
                    }
                }
            }
            Err(err) => {
                first_err.get_or_insert(io_err(&dir, err));
            }
        }
        dirs.push((depth, dir));
    }

    let (n, e) = par_delete(&leaves);
    stats.files += n;
    let mut first_err = first_err.or(e);
    dirs.sort_by(|a, b| b.0.cmp(&a.0));
    for level in dirs.chunk_by(|a, b| a.0 == b.0) {
        let level: Vec<(PathBuf, bool)> = level.iter().map(|(_, p)| (p.clone(), true)).collect();
        let (n, e) = par_delete(&level);
        stats.dirs += n;
        first_err = first_err.or(e);
    }
    first_err.map_or(Ok(()), Err)
}

/// Deletes a batch of independent entries on several threads and returns only after trying them all:
/// (number deleted, first error).
fn par_delete(items: &[(PathBuf, bool)]) -> (u64, Option<DeleteError>) {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, 8);
    let next = AtomicUsize::new(0);
    let done = AtomicU64::new(0);
    let first_err: std::sync::Mutex<Option<DeleteError>> = std::sync::Mutex::new(None);
    let work = || {
        while let Some((p, is_dir)) = items.get(next.fetch_add(1, Ordering::Relaxed)) {
            match delete_entry(p, *is_dir) {
                Ok(()) => {
                    done.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    first_err.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert(e);
                }
            }
        }
    };
    if items.len() < 64 {
        work(); // not worth spawning threads for a few items
    } else {
        std::thread::scope(|sc| {
            for _ in 0..workers.min(items.len()) {
                sc.spawn(work);
            }
        });
    }
    (done.into_inner(), first_err.into_inner().unwrap_or_else(|p| p.into_inner()))
}

/// Deletes one entry. Already gone counts as success; access denied / sharing violation / lock violation /
/// directory not empty are retried a few times with backoff.
fn delete_entry(p: &Path, is_dir: bool) -> Result<(), DeleteError> {
    const TRANSIENT: [i32; 4] = [5, 32, 33, 145];
    let mut last: Option<std::io::Error> = None;
    for delay_ms in [0u64, 2, 10, 50] {
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        if try_posix_delete(p) {
            return Ok(());
        }
        clear_readonly(p);
        match if is_dir { std::fs::remove_dir(p) } else { std::fs::remove_file(p) } {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                let transient = e.raw_os_error().is_some_and(|c| TRANSIENT.contains(&c));
                last = Some(e);
                if !transient {
                    break;
                }
            }
        }
    }
    Err(io_err(p, last.unwrap_or_else(|| std::io::Error::other("delete failed"))))
}

/// POSIX-semantics delete (Win10 1809+): the name goes away immediately, the data when the last reference
/// is released. Returns false where unsupported (FAT32 etc.).
fn try_posix_delete(path: &Path) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_FORCE_IMAGE_SECTION_CHECK,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
        FILE_DISPOSITION_INFO_EX_FLAGS, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfoEx, OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
    };
    use windows::core::PCWSTR;
    let w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let Ok(h) = CreateFileW(
            PCWSTR(w.as_ptr()),
            DELETE.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        ) else {
            return false;
        };
        let info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
                FILE_DISPOSITION_FLAG_DELETE.0
                    | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                    | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0
                    | FILE_DISPOSITION_FLAG_FORCE_IMAGE_SECTION_CHECK.0,
            ),
        };
        let ok = SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
        .is_ok();
        let _ = CloseHandle(h);
        ok
    }
}

fn clear_readonly(path: &Path) {
    if let Ok(md) = std::fs::symlink_metadata(path) {
        let mut perms = md.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

fn io_err(path: &Path, e: std::io::Error) -> DeleteError {
    DeleteError::Io { path: strip_long_prefix(path), err: e.to_string() }
}

/// Adds the `\\?\` prefix to `X:\...`; already-prefixed / UNC / relative paths are returned as is.
fn to_long_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let b = s.as_bytes();
    if !s.starts_with(r"\\") && b.len() >= 3 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/') {
        PathBuf::from(format!(r"\\?\{}", s.replace('/', "\\")))
    } else {
        p.to_path_buf()
    }
}

fn strip_long_prefix(p: &Path) -> String {
    let s = p.to_string_lossy().into_owned();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Dangerous paths: drive roots / %SystemRoot% / Program Files (x86) / ProgramData / the Users folder /
/// the current user profile. Only these folders **themselves** are blocked, not their subfolders
/// (deleting `C:\Users\me\proj\node_modules` is fine, deleting `C:\Users\me` is not).
pub fn is_protected_path(target: &Path) -> bool {
    let norm = normalize(target);
    if norm.is_empty() {
        return true;
    }
    if norm.len() <= 2 && norm.ends_with(':') {
        return true;
    }
    let mut protected: Vec<String> = ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "USERPROFILE"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .map(|v| normalize(Path::new(&v)))
        .collect();
    if let Ok(drive) = std::env::var("SystemDrive") {
        protected.push(normalize(Path::new(&format!("{drive}\\Users"))));
    }
    protected.iter().any(|p| !p.is_empty() && *p == norm)
}

/// Lowercase + strip `\\?\` + strip the trailing `\`, for equality checks.
fn normalize(p: &Path) -> String {
    strip_long_prefix(p).replace('/', "\\").to_lowercase().trim_end_matches('\\').to_string()
}

// ── Delete on reboot ─────────────────────────────────────────────

/// Schedules deletion at the next reboot (`MoveFileExW` + `MOVEFILE_DELAY_UNTIL_REBOOT`; the system runs it
/// before other programs start, so no lock can stop it). **Requires admin** (the list lives in HKLM).
/// Folders: files first, then subdirectories deepest first (the system processes entries in order, and a
/// directory must be empty by the time it's deleted). Returns the number of entries scheduled.
pub fn schedule_delete_on_reboot(target: &Path) -> usize {
    use windows::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
    let Ok(md) = std::fs::symlink_metadata(target) else { return 0 };
    if is_protected_path(target) {
        return 0;
    }
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    collect_post_order(&to_long_path(target), md.file_type(), &mut files, &mut dirs);
    files
        .iter()
        .chain(dirs.iter())
        .filter(|p| {
            clear_readonly(p);
            let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
            let ok = unsafe { MoveFileExW(windows::core::PCWSTR(w.as_ptr()), None, MOVEFILE_DELAY_UNTIL_REBOOT) }.is_ok();
            if !ok {
                log::warn!("reboot-delete: failed to schedule {}", strip_long_prefix(p));
            }
            ok
        })
        .count()
}

fn collect_post_order(path: &Path, ft: std::fs::FileType, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    if ft.is_dir() && !ft.is_symlink() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                if let Ok(cft) = e.file_type() {
                    collect_post_order(&e.path(), cft, files, dirs);
                }
            }
        }
        dirs.push(path.to_path_buf());
    } else if ft.is_dir() {
        dirs.push(path.to_path_buf()); // directory link: delete the link only
    } else {
        files.push(path.to_path_buf());
    }
}

/// Schedules a batch of paths for deletion on reboot and returns the number of entries scheduled;
/// `None` = admin rights weren't granted (UAC declined). If already elevated, schedules directly;
/// otherwise writes the list to a temp file, relaunches this exe as admin with
/// `--delete-on-reboot <list>` and waits for it to exit (exit code = entry count).
/// **Blocks until the helper exits**, so don't expect it to return right away.
pub fn schedule_reboot_delete(paths: &[PathBuf]) -> Option<usize> {
    if is_elevated() {
        return Some(paths.iter().map(|p| schedule_delete_on_reboot(p)).sum());
    }
    let list = std::env::temp_dir().join(format!("obunlock-reboot-{}.txt", std::process::id()));
    let text: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    std::fs::write(&list, text.join("\n")).ok()?;
    let code = run_as_admin_and_wait(&format!("{REBOOT_DELETE_ARG} \"{}\"", list.display()));
    let _ = std::fs::remove_file(&list); // if UAC was declined the helper never ran, so clean up here
    code.map(|c| c as usize)
}

/// Elevated helper entry point: if the command line is `--delete-on-reboot <list>`, schedules the paths,
/// deletes the list and returns the exit code (= entry count); otherwise None.
pub fn run_reboot_delete_helper() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some(REBOOT_DELETE_ARG) {
        return None;
    }
    let list = PathBuf::from(args.next()?);
    let text = std::fs::read_to_string(&list).unwrap_or_default();
    let _ = std::fs::remove_file(&list);
    let n: usize = text.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| schedule_delete_on_reboot(Path::new(l))).sum();
    Some(n as i32)
}

/// Whether the current process is elevated (admin).
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut el = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut el as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && el.TokenIsElevated != 0
    }
}

/// Runs this exe as admin (hidden window), waits for it to exit and returns its exit code.
/// None if UAC is declined or the launch fails.
fn run_as_admin_and_wait(args: &str) -> Option<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::{PCWSTR, w};
    let exe = std::env::current_exe().ok()?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let args_w: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(args_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        ShellExecuteExW(&mut sei).ok()?;
        if sei.hProcess.is_invalid() {
            return None;
        }
        WaitForSingleObject(sei.hProcess, INFINITE);
        let mut code = 0u32;
        let ok = GetExitCodeProcess(sei.hProcess, &mut code).is_ok();
        let _ = CloseHandle(sei.hProcess);
        ok.then_some(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("obunlock_del_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn protected_paths() {
        assert!(is_protected_path(Path::new(r"C:\")));
        assert!(is_protected_path(Path::new("C:")));
        let sys = std::env::var("SystemRoot").unwrap();
        assert!(is_protected_path(Path::new(&sys)));
        assert!(is_protected_path(Path::new(&format!(r"\\?\{sys}\"))), "prefix / trailing slash don't matter");
        let home = std::env::var("USERPROFILE").unwrap();
        assert!(is_protected_path(Path::new(&home)));
        assert!(!is_protected_path(Path::new(&format!(r"{home}\proj\node_modules"))), "subfolders are not blocked");
    }

    /// Read-only files, deep nesting, paths over MAX_PATH and 100+ files (multithreaded path) all get deleted
    #[test]
    fn deletes_tree_with_readonly_and_long_paths() {
        let root = tmp("tree");
        let mut deep = root.clone();
        for i in 0..12 {
            deep = deep.join(format!("level_{i:02}_padding_padding_padding"));
        }
        std::fs::create_dir_all(to_long_path(&deep)).unwrap();
        std::fs::write(to_long_path(&deep.join("deep.txt")), b"x").unwrap();
        for i in 0..120 {
            std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
        }
        let ro = root.join("ro.txt");
        std::fs::write(&ro, b"x").unwrap();
        let mut perm = std::fs::metadata(&ro).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&ro, perm).unwrap();
        assert!(deep.to_string_lossy().len() > 260);

        let st = force_delete(&root).expect("everything should be deleted");
        assert_eq!(st.files, 122);
        assert!(!root.exists());
    }

    /// A junction is deleted as a link only; what it points to stays untouched
    #[test]
    fn junction_deletes_link_only() {
        let root = tmp("junc");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("keep.txt"), b"x").unwrap();
        let victim = root.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let link = victim.join("link");
        let ok = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &link.to_string_lossy(), &real.to_string_lossy()])
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "mklink /J failed");
        force_delete(&victim).expect("should be deleted");
        assert!(!victim.exists());
        assert!(real.join("keep.txt").exists(), "the link target must not be deleted");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_is_not_found() {
        assert!(matches!(force_delete(Path::new(r"C:\definitely\not\here\x")), Err(DeleteError::NotFound)));
    }
}
