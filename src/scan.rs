//! Find out "who is locking this file / folder", and unlock it (close the handle / end the process).
//!
//! Four complementary scans run in parallel (total time ≈ the slowest one):
//! 1. System-wide handle scan (`Handle`, closable): `NtQuerySystemInformation(SystemExtendedHandleInformation)`
//!    → `DuplicateHandle` each into this process → `NtQueryObject` for the type (keep File) and the object
//!    name (NT device path) → compare.
//! 2. Mapping scan (`Image`): the process's main exe / a loaded DLL / a memory-mapped data file is inside
//!    the target. That's a Section, not a File handle, so scan 1 can't see it (this is why the folder of a
//!    running program can't be deleted).
//! 3. File-side lookup (`InUse`, FileProcessIdsUsingFileInformation): ask the file "who has you open"; sees
//!    processes scan 1 can't open (protected processes / admin processes when not elevated / System).
//!    For folders, the entries inside are walked (with a cap).
//! 4. Restart Manager (`InUse`): the official "file in use" mechanism, files only.
//!
//! ## Hangs and speed
//! - `NtQueryObject(name)` hangs forever on named pipes and similar handles: first `GetFileType` so only
//!   disk files get a name query, then run it on a worker thread with a timeout; if it hangs, abandon that
//!   thread and start a new one (one scan leaks at most a handful of threads / handles).
//!   **Don't skip GrantedAccess == 0x0012019F**: that's exactly the mask of a file opened with
//!   GENERIC_READ | GENERIC_WRITE. Skipping it misses every file opened for read-write (Office / editors /
//!   databases); this has caused missed detections in practice.
//! - The ObjectTypeIndex of the File type is cached once identified, so non-File handles aren't even duplicated.
//! - One kernel file object is often shared by many handles (system DLLs are open in dozens of processes),
//!   so names are cached by object pointer and queried only once.
//! - The handle scan has an overall budget, [`BUDGET`]; in extreme environments it returns what it has found
//!   when time runs out.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess,
};
use windows::core::{PCWSTR, s, w};

use crate::process::{
    KILL_PROTECTED, enable_se_debug_privilege, is_critical_process, process_basename, process_image_path,
    process_start_time, process_start_time_of,
};

/// One lock record: a process locks target number `target` in some way. A process may have several.
#[derive(Debug, Clone)]
pub struct Locker {
    pub pid: u32,
    pub name: String,
    /// Handle value **in the source process** (non-zero only when `kind == Handle`), used to force-close it.
    pub handle: usize,
    /// Process creation time (0 = unknown). Re-checked before acting, so an innocent new process with a
    /// reused PID isn't hit.
    pub start: u64,
    /// Index of the matched target (into the `find_lockers` argument). With nested targets, only the first
    /// match is recorded.
    pub target: usize,
    pub kind: LockKind,
    /// NT path this handle pointed to at scan time (lowercase, `Handle` only). Checked again before closing:
    /// between the scan and the user clicking OK, the process may close the handle and the kernel may hand
    /// the same value to another file; without the check, the wrong handle would be closed silently.
    pub nt_path: String,
}

/// Where a lock was found. Decides how to unlock and how to dedupe: when the same (pid, target) already has
/// a Handle / Image record, InUse is redundant, and keeping it would make "unlock" end a process that only
/// needed a handle closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// Found by the handle scan; the handle can be closed.
    Handle,
    /// The process has the target mapped into memory (main exe / DLL / mapped data file). No handle to
    /// close, so the process has to be ended.
    Image,
    /// The file system / Restart Manager says it's in use, but the handle scan can't see it (protected /
    /// not enough rights). The process has to be ended.
    InUse,
}

/// Overall budget for the handle scan: when it runs out, return what has been found. A one-off operation
/// with the user waiting; this is plenty.
const BUDGET: Duration = Duration::from_secs(12);
/// Name query timeout per handle. Disk-file name queries take microseconds and pipes are already filtered
/// out by GetFileType; this is a safety net.
const NAME_TIMEOUT: Duration = Duration::from_millis(80);
/// Caps on how many entries inside a folder the file-side lookup asks about, and for how long (opening
/// every file in node_modules is too slow; this is only a fallback).
const IN_USE_MAX_ENTRIES: usize = 20_000;
const IN_USE_BUDGET: Duration = Duration::from_millis(1500);

// ── ntdll dynamic binding ───────────────────────────────────────

type NtQuerySystemInformationFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type NtQueryObjectFn = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
type NtQueryInformationFileFn = unsafe extern "system" fn(HANDLE, *mut IoStatusBlock, *mut c_void, u32, u32) -> i32;

const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPE_INFORMATION: u32 = 2;
const FILE_PROCESS_IDS_USING_FILE_INFORMATION: u32 = 47;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;

fn ntdll_fn(name: windows::core::PCSTR, cell: &'static OnceLock<Option<usize>>) -> Option<usize> {
    *cell.get_or_init(|| unsafe {
        let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
        GetProcAddress(ntdll, name).map(|p| p as usize)
    })
}

fn nt_query_system_information() -> Option<NtQuerySystemInformationFn> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    ntdll_fn(s!("NtQuerySystemInformation"), &F).map(|a| unsafe { std::mem::transmute(a) })
}

fn nt_query_object() -> Option<NtQueryObjectFn> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    ntdll_fn(s!("NtQueryObject"), &F).map(|a| unsafe { std::mem::transmute(a) })
}

fn nt_query_information_file() -> Option<NtQueryInformationFileFn> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    ntdll_fn(s!("NtQueryInformationFile"), &F).map(|a| unsafe { std::mem::transmute(a) })
}

// ── Kernel structures (x64 layout) ──────────────────────────────

#[repr(C)]
struct SystemHandleTableEntryInfoEx {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct SystemHandleInformationEx {
    number_of_handles: usize,
    reserved: usize,
    // followed by handles: [SystemHandleTableEntryInfoEx; number_of_handles]
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct IoStatusBlock {
    status: usize,
    information: usize,
}

// ── Targets ──────────────────────────────────────────────────────

/// A target to compare against. `nt` has the same form as NtQueryObject / GetMappedFileName output
/// (`\device\harddiskvolume3\...`), `dos` the same form as process image paths (`c:\...`); both are lowercase
/// with no trailing `\`. Both are **final paths** (GetFinalPathNameByHandle): 8.3 short names / subst drives /
/// mount points are expanded to what the kernel actually records, and network paths (`\device\mup\...`)
/// compare too. If the target can't be opened, falls back to string conversion.
struct Spec {
    nt: String,
    dos: String,
    is_dir: bool,
    idx: usize,
}

impl Spec {
    /// `name` (already lowercase) matches: equal, or the target is a folder and `name` is inside it.
    fn hit(&self, name: &str, use_nt: bool) -> bool {
        hit(if use_nt { &self.nt } else { &self.dos }, self.is_dir, name)
    }
}

fn hit(t: &str, is_dir: bool, name: &str) -> bool {
    name == t || (is_dir && name.len() > t.len() && name.starts_with(t) && name.as_bytes()[t.len()] == b'\\')
}

fn build_specs(targets: &[(PathBuf, bool)]) -> Vec<Spec> {
    let trim = |s: String| s.trim_end_matches('\\').to_string();
    targets
        .iter()
        .enumerate()
        .filter_map(|(idx, (p, is_dir))| {
            let nt = final_path(p, true).or_else(|| dos_to_nt_path(p))?.to_lowercase();
            let dos = final_path(p, false)
                .map(|s| normalize_win32_path(&s))
                .unwrap_or_else(|| normalize_win32_path(&p.to_string_lossy()));
            Some(Spec { nt: trim(nt), dos: trim(dos), is_dir: *is_dir, idx })
        })
        .collect()
}

/// Gets the final path by opening with attribute access only (not subject to share modes, so it opens even
/// when exclusively locked). `nt=true` returns the `\Device\...` form, otherwise the DOS form (with `\\?\`).
fn final_path(p: &Path, nt: bool) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW};
    const VOLUME_NAME_NT: u32 = 0x2;
    let h = open_attr_only(p)?;
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | if nt { VOLUME_NAME_NT } else { 0 });
    let mut buf = vec![0u16; 1024];
    let mut n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, flags) } as usize;
    if n >= buf.len() {
        buf = vec![0u16; n + 1];
        n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, flags) } as usize;
    }
    unsafe {
        let _ = CloseHandle(h);
    }
    (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]))
}

/// Opens a file or directory with FILE_READ_ATTRIBUTES only (BACKUP_SEMANTICS allows opening directories).
fn open_attr_only(p: &Path) -> Option<HANDLE> {
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .ok()
}

// ── Public API ───────────────────────────────────────────────────

/// Finds every process locking any of the targets (files or folders). For a folder, a lock on anything
/// inside it counts too (the usual reason it can't be deleted). Results are deduped by (pid, target): InUse
/// is dropped where Handle / Image already exists.
///
/// **Call it off the UI thread**: a system-wide scan takes hundreds of ms to a few seconds. Returns an empty
/// list on failure or when nothing is locked.
pub fn find_lockers(targets: &[PathBuf]) -> Vec<Locker> {
    enable_se_debug_privilege();
    let t0 = Instant::now();
    // symlink_metadata: a junction / link itself doesn't count as a folder (only the link gets deleted)
    let targets: Vec<(PathBuf, bool)> =
        targets.iter().map(|p| (p.clone(), std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))).collect();
    let specs = build_specs(&targets);
    if specs.is_empty() {
        return Vec::new();
    }

    let specs = &specs;
    let targets = &targets;
    // Run all four scans at once (scan 4 on this thread); total time ≈ the slowest one
    let (mut lockers, [t_handles, t_images, t_in_use, t_rm]) = std::thread::scope(|sc| {
        let timed = |f: fn(&[Spec]) -> Vec<Locker>| {
            move || {
                let t = Instant::now();
                (f(specs), t.elapsed())
            }
        };
        let handles = sc.spawn(timed(handle_lockers));
        let images = sc.spawn(timed(image_lockers));
        let in_use = sc.spawn(|| {
            let t = Instant::now();
            (in_use_lockers(targets), t.elapsed())
        });
        let t = Instant::now();
        let mut out = restart_manager_lockers(targets);
        let tr = t.elapsed();
        let (u, tu) = in_use.join().unwrap_or_default();
        let (h, th) = handles.join().unwrap_or_default();
        let (i, ti) = images.join().unwrap_or_default();
        out.extend(u);
        out.extend(h);
        out.extend(i);
        (out, [th, ti, tu, tr])
    });

    let strong: std::collections::HashSet<(u32, usize)> =
        lockers.iter().filter(|l| l.kind != LockKind::InUse).map(|l| (l.pid, l.target)).collect();
    let mut seen_weak = std::collections::HashSet::new();
    lockers.retain(|l| l.kind != LockKind::InUse || (!strong.contains(&(l.pid, l.target)) && seen_weak.insert((l.pid, l.target))));

    for l in &lockers {
        log::info!("unlock: target#{} locked by {} (pid {}, {:?}, handle {:#x})", l.target, l.name, l.pid, l.kind, l.handle);
    }
    log::info!(
        "unlock: scan done, {} targets, {} records ({}ms: handles {}ms, images {}ms, in-use {}ms, rm {}ms)",
        targets.len(),
        lockers.len(),
        t0.elapsed().as_millis(),
        t_handles.as_millis(),
        t_images.as_millis(),
        t_in_use.as_millis(),
        t_rm.as_millis(),
    );
    lockers
}

/// Unlocking this record means ending the process, and that process may be ended. Use it to decide whether
/// to warn "this will end the process" before unlocking.
pub fn will_kill(l: &Locker) -> bool {
    l.handle == 0 && !is_critical_process(l.pid)
}

/// Unlock: close the handles that can be closed; end the processes with no handle to close (mapped / only
/// known to be in use), which the caller has already confirmed. System-critical processes are never
/// touched either way. Returns the number of locks released.
pub fn release(lockers: &[Locker]) -> usize {
    let mut n = lockers.iter().filter(|l| l.handle != 0 && close_handle(l)).count();
    let mut seen: Vec<u32> = Vec::new();
    for l in lockers.iter().filter(|l| l.handle == 0) {
        if !seen.contains(&l.pid) {
            seen.push(l.pid);
            n += terminate(l.pid, l.start) as usize;
        }
    }
    n
}

/// Forceful mode: end every locking process (still skipping critical processes / explorer). Returns how many
/// were ended.
pub fn kill_all(lockers: &[Locker]) -> usize {
    let mut seen: Vec<u32> = Vec::new();
    let mut n = 0;
    for l in lockers {
        if !seen.contains(&l.pid) {
            seen.push(l.pid);
            n += terminate(l.pid, l.start) as usize;
        }
    }
    n
}

// ── Scan 1: handles ─────────────────────────────────────────────

/// Process name / creation time cached by pid (several scans need them).
#[derive(Default)]
struct ProcInfoCache {
    names: std::collections::HashMap<u32, String>,
    starts: std::collections::HashMap<u32, u64>,
}

impl ProcInfoCache {
    fn locker(&mut self, pid: u32, handle: usize, target: usize, kind: LockKind, nt_path: &str) -> Locker {
        let name = self
            .names
            .entry(pid)
            .or_insert_with(|| if pid == 4 { "System".into() } else { process_basename(pid).unwrap_or_else(|| format!("PID {pid}")) })
            .clone();
        let start = *self.starts.entry(pid).or_insert_with(|| process_start_time(pid).unwrap_or(0));
        Locker { pid, name, handle, start, target, kind, nt_path: nt_path.to_string() }
    }
}

fn handle_lockers(specs: &[Spec]) -> Vec<Locker> {
    let (Some(nt_qsi), Some(nt_qo)) = (nt_query_system_information(), nt_query_object()) else {
        return Vec::new();
    };
    let Some(buf) = snapshot_handles(nt_qsi) else {
        return Vec::new();
    };
    let header = unsafe { &*(buf.as_ptr() as *const SystemHandleInformationEx) };
    let count = header.number_of_handles;
    let entries_ptr =
        unsafe { buf.as_ptr().add(std::mem::size_of::<SystemHandleInformationEx>()) as *const SystemHandleTableEntryInfoEx };

    let our_pid = unsafe { GetCurrentProcessId() };
    let our_proc = unsafe { GetCurrentProcess() };
    let mut proc_cache: std::collections::HashMap<u32, HANDLE> = std::collections::HashMap::new();
    let mut info = ProcInfoCache::default();
    let mut file_type_index: Option<u16> = None;
    let mut lockers: Vec<Locker> = Vec::new();
    let mut querier = NameQuerier::new();
    // kernel object pointer → object name (None = unnamed / query failed / not a disk file)
    let mut obj_names: std::collections::HashMap<usize, Option<String>> = std::collections::HashMap::new();
    let started = Instant::now();

    let mut record = |name: &str, entry: &SystemHandleTableEntryInfoEx, pid: u32, lockers: &mut Vec<Locker>| {
        if let Some(s) = specs.iter().find(|s| s.hit(name, true)) {
            lockers.push(info.locker(pid, entry.handle_value, s.idx, LockKind::Handle, name));
        }
    };

    for i in 0..count {
        if started.elapsed() > BUDGET {
            log::warn!("unlock: handle scan over budget after {i}/{count}, returning early");
            break;
        }
        let entry = unsafe { &*entries_ptr.add(i) };
        let pid = entry.unique_process_id as u32;
        // Don't skip System (pid 4): file handles opened by drivers / SMB shares live under it.
        // Shown only, never closed (see close_handle)
        if pid == our_pid || pid == 0 {
            continue;
        }
        if file_type_index.is_some_and(|idx| entry.object_type_index != idx) {
            continue;
        }
        // When not elevated (Win11 24H2+ without SeDebugPrivilege), kernel object pointers are all zeroed and
        // can't be a cache key, or the first handle's name would be applied to every handle. For 0, skip the
        // cache and query each name
        let obj = entry.object as usize;
        if let Some(cached) = obj_names.get(&obj).filter(|_| obj != 0) {
            if let Some(name) = cached {
                record(name, entry, pid, &mut lockers);
            }
            continue;
        }

        let src = *proc_cache
            .entry(pid)
            .or_insert_with(|| unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }.unwrap_or_default());
        if src.is_invalid() {
            continue; // can't open it (rights / already exited) → scan 3 covers it
        }
        let mut dup = HANDLE::default();
        let ok = unsafe {
            DuplicateHandle(src, HANDLE(entry.handle_value as *mut c_void), our_proc, &mut dup, 0, false, DUPLICATE_SAME_ACCESS)
        }
        .is_ok();
        if !ok || dup.is_invalid() {
            continue;
        }
        if file_type_index.is_none() {
            match query_type_name(nt_qo, dup) {
                Some(t) if t.eq_ignore_ascii_case("File") => file_type_index = Some(entry.object_type_index),
                _ => {
                    unsafe {
                        let _ = CloseHandle(dup);
                    }
                    continue;
                }
            }
        }
        match querier.query(dup.0 as usize) {
            QueryResult::Ok(name) => {
                let name = name.map(|n| n.to_lowercase());
                if let Some(n) = &name {
                    record(n, entry, pid, &mut lockers);
                }
                if obj != 0 {
                    obj_names.insert(obj, name);
                }
                unsafe {
                    let _ = CloseHandle(dup);
                }
            }
            QueryResult::TimedOut => {
                // Hung: record as unnamed (don't hang on the same object again), abandon dup (the old worker
                // may still be using it), start a new worker
                if obj != 0 {
                    obj_names.insert(obj, None);
                }
                querier = NameQuerier::new();
            }
        }
    }

    for (_, h) in proc_cache {
        if !h.is_invalid() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }
    lockers
}

// ── Scan 2: mappings ────────────────────────────────────────────

/// Walks the other process's address space region by region with `VirtualQueryEx`; for each MEM_IMAGE /
/// MEM_MAPPED allocation (once per AllocationBase), gets the NT path with `GetMappedFileNameW` and compares.
/// For processes whose memory can't be opened, falls back to comparing only the main exe path.
/// A process may both hold a handle and map the target: Handle closes the handle, Image ends the process,
/// so don't dedupe across kinds.
fn image_lockers(specs: &[Spec]) -> Vec<Locker> {
    let pids = all_pids();
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).min(8);
    let chunk = pids.len().div_ceil(workers).max(1);
    std::thread::scope(|sc| {
        let jobs: Vec<_> = pids.chunks(chunk).map(|c| sc.spawn(move || image_lockers_for(c, specs))).collect();
        jobs.into_iter().flat_map(|j| j.join().unwrap_or_default()).collect()
    })
}

fn image_lockers_for(pids: &[u32], specs: &[Spec]) -> Vec<Locker> {
    use windows::Win32::System::Memory::{MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
    use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
    use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let our_pid = unsafe { GetCurrentProcessId() };
    let mut info = ProcInfoCache::default();
    let mut lockers = Vec::new();
    let mut name_buf = vec![0u16; 1024];

    for &pid in pids {
        if pid == our_pid || pid <= 4 {
            continue; // System has no user-mode mappings
        }
        let mut hits: Vec<usize> = Vec::new();
        let mut add = |idx: usize| {
            if !hits.contains(&idx) {
                hits.push(idx);
            }
        };
        match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
            Ok(h) => {
                let mut addr: usize = 0;
                let mut last_base: usize = usize::MAX;
                let mut mbi = MEMORY_BASIC_INFORMATION::default();
                let mbi_len = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
                while unsafe { VirtualQueryEx(h, Some(addr as *const c_void), &mut mbi, mbi_len) } == mbi_len {
                    let base = mbi.AllocationBase as usize;
                    if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) && base != last_base {
                        last_base = base;
                        let n = unsafe { GetMappedFileNameW(h, mbi.AllocationBase, &mut name_buf) } as usize;
                        if n > 0 {
                            let name = String::from_utf16_lossy(&name_buf[..n]).to_lowercase();
                            for s in specs.iter().filter(|s| s.hit(&name, true)) {
                                add(s.idx);
                            }
                        }
                    }
                    let next = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
                    if next <= addr {
                        break;
                    }
                    addr = next;
                }
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
            Err(_) => {
                if let Some(exe) = process_image_path(pid) {
                    let exe = normalize_win32_path(&exe);
                    for s in specs.iter().filter(|s| s.hit(&exe, false)) {
                        add(s.idx);
                    }
                }
            }
        }
        for target in hits {
            lockers.push(info.locker(pid, 0, target, LockKind::Image, ""));
        }
    }
    lockers
}

fn all_pids() -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
    };
    let mut pids = Vec::new();
    unsafe {
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
            if Process32FirstW(snap, &mut e).is_ok() {
                loop {
                    pids.push(e.th32ProcessID);
                    if Process32NextW(snap, &mut e).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }
    pids
}

// ── Scan 3: file-side lookup ────────────────────────────────────

fn in_use_lockers(targets: &[(PathBuf, bool)]) -> Vec<Locker> {
    let Some(nt_qif) = nt_query_information_file() else {
        return Vec::new();
    };
    let our_pid = unsafe { GetCurrentProcessId() };
    let deadline = Instant::now() + IN_USE_BUDGET;
    // First list what to ask about (path, target index, is it the selected item itself), walking into
    // folders; then split the queries across threads. Each query takes ~40ms (measured, regardless of
    // opening the file), so asking about 40 files serially takes over a second
    let mut ask: Vec<(PathBuf, usize, bool)> = Vec::new();
    for (idx, (root, is_dir)) in targets.iter().enumerate() {
        let mut stack = vec![root.clone()];
        while let Some(p) = stack.pop() {
            if *is_dir && ask.len() < IN_USE_MAX_ENTRIES && Instant::now() < deadline {
                for e in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                    match e.file_type() {
                        Ok(ft) if ft.is_symlink() => {} // what a junction / link points to isn't in this folder
                        Ok(ft) if ft.is_dir() => stack.push(e.path()),
                        Ok(_) => ask.push((e.path(), idx, false)),
                        Err(_) => {}
                    }
                }
            }
            let is_root = &p == root;
            ask.push((p, idx, is_root));
        }
    }
    let hits = par_flat_map(&ask, |(p, idx, root)| {
        // Always ask about the selected item itself; entries inside folders are skipped once time is up
        if !root && Instant::now() >= deadline {
            return Vec::new();
        }
        pids_using(nt_qif, p).into_iter().filter(|&pid| pid != our_pid && pid != 0).map(|pid| (pid, *idx)).collect()
    });
    if ask.len() >= IN_USE_MAX_ENTRIES || Instant::now() >= deadline {
        log::info!("unlock: in-use walk stopped early after {} entries", ask.len());
    }
    let mut info = ProcInfoCache::default();
    let mut found = std::collections::HashSet::new();
    hits.into_iter().filter(|&h| found.insert(h)).map(|(pid, idx)| info.locker(pid, 0, idx, LockKind::InUse, "")).collect()
}

/// Threads used to query the system in parallel. in_use / RM take tens to 100+ ms per file; measured with
/// 40 files on 8 threads: in_use 1.6s → 0.24s, RM 5.8s → 0.88s
const PAR_THREADS: usize = 8;

/// Splits items evenly across up to PAR_THREADS threads, runs f on each and concatenates the results
/// (each result carries its own owner, so order doesn't matter)
fn par_flat_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> Vec<R> + Sync) -> Vec<R> {
    if items.is_empty() {
        return Vec::new();
    }
    let f = &f;
    std::thread::scope(|sc| {
        let hs: Vec<_> = items
            .chunks(items.len().div_ceil(PAR_THREADS))
            .map(|c| sc.spawn(move || c.iter().flat_map(f).collect::<Vec<R>>()))
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    })
}

/// PIDs of processes that have `p` open (including this one: we hold it open while querying).
fn pids_using(nt_qif: NtQueryInformationFileFn, p: &Path) -> Vec<u32> {
    let Some(h) = open_attr_only(p) else { return Vec::new() };
    // FILE_PROCESS_IDS_USING_FILE_INFORMATION: a ULONG count, then (after alignment) ULONG_PTR[]
    let mut buf = vec![0usize; 64];
    let mut pids = Vec::new();
    for _ in 0..4 {
        let mut iosb = IoStatusBlock { status: 0, information: 0 };
        let st = unsafe {
            nt_qif(
                h,
                &mut iosb,
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * std::mem::size_of::<usize>()) as u32,
                FILE_PROCESS_IDS_USING_FILE_INFORMATION,
            )
        };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            buf = vec![0usize; buf.len() * 4];
            continue;
        }
        if st >= 0 {
            let n = (buf[0] & 0xFFFF_FFFF).min(buf.len() - 1);
            pids = buf[1..=n].iter().map(|&p| p as u32).collect();
        }
        break;
    }
    unsafe {
        let _ = CloseHandle(h);
    }
    pids
}

// ── Scan 4: Restart Manager ─────────────────────────────────────

/// Files only (a directory can't be loaded as a module, and RM doesn't recurse). One session per file:
/// RmGetList doesn't say which resource matched, so a shared session couldn't attribute results to files.
/// A session on a locked file takes ~135ms, so sessions are spread across threads.
fn restart_manager_lockers(targets: &[(PathBuf, bool)]) -> Vec<Locker> {
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
    };
    use windows::core::PWSTR;

    let our_pid = unsafe { GetCurrentProcessId() };
    let files: Vec<(usize, &PathBuf)> = targets.iter().enumerate().filter(|(_, (_, d))| !d).map(|(i, (p, _))| (i, p)).collect();
    par_flat_map(&files, |&(idx, path)| {
        let mut lockers = Vec::new();
        let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut session: u32 = 0;
        let mut key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        if unsafe { RmStartSession(&mut session, None, PWSTR(key.as_mut_ptr())) } != ERROR_SUCCESS {
            return lockers;
        }
        if unsafe { RmRegisterResources(session, Some(&[PCWSTR(path_w.as_ptr())]), None, None) } == ERROR_SUCCESS {
            let (mut needed, mut count, mut reboot) = (0u32, 0u32, 0u32);
            let first = unsafe { RmGetList(session, &mut needed, &mut count, None, &mut reboot) };
            if (first == ERROR_SUCCESS || first == ERROR_MORE_DATA) && needed > 0 {
                let mut buf: Vec<RM_PROCESS_INFO> = vec![unsafe { std::mem::zeroed() }; needed as usize];
                count = buf.len() as u32;
                let second = unsafe { RmGetList(session, &mut needed, &mut count, Some(buf.as_mut_ptr()), &mut reboot) };
                if second == ERROR_SUCCESS || second == ERROR_MORE_DATA {
                    for info in buf.iter().take(count as usize) {
                        let pid = info.Process.dwProcessId;
                        if pid == our_pid || pid == 0 || pid == 4 {
                            continue;
                        }
                        let name = process_basename(pid).unwrap_or_else(|| format!("PID {pid}"));
                        let t = info.Process.ProcessStartTime;
                        let start = ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64;
                        lockers.push(Locker { pid, name, handle: 0, start, target: idx, kind: LockKind::InUse, nt_path: String::new() });
                    }
                }
            }
        }
        unsafe {
            let _ = RmEndSession(session);
        }
        lockers
    })
}

// ── Unlocking ────────────────────────────────────────────────────

/// Force-closes the handle recorded in `l` (DuplicateHandle + DUPLICATE_CLOSE_SOURCE closes it in the
/// source process).
///
/// **Dangerous**: the target program doesn't know its handle is gone; using it again may crash it or
/// corrupt data. The caller must have confirmed. Three checks before acting: the process creation time
/// matches → duplicate it once read-only to see what it points to now → close it only if the path matches
/// the scan. System-critical processes are always refused: System's handle table is the kernel handle
/// table, and closing a handle a driver is using blue-screens the machine.
pub fn close_handle(l: &Locker) -> bool {
    if l.handle == 0 || l.nt_path.is_empty() {
        return false; // no handle to close (mapped / only known to be in use); the process has to be ended
    }
    if is_critical_process(l.pid) {
        log::warn!("unlock: refusing to close a handle in system-critical process {} (pid {})", l.name, l.pid);
        return false;
    }
    enable_se_debug_privilege();
    unsafe {
        let Ok(src) = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, l.pid) else {
            return false;
        };
        let bail = |why: String| {
            log::warn!("unlock: not closing handle in {} (pid {}): {why}", l.name, l.pid);
            let _ = CloseHandle(src);
            false
        };

        // Check 1: the PID hasn't been reused
        if l.start != 0 && process_start_time_of(src).is_some_and(|now| now != l.start) {
            return bail("creation time differs from the scan, PID was reused".into());
        }

        // Check 2: duplicate it **without** CLOSE_SOURCE to see what this handle value points to now
        let mut probe = HANDLE::default();
        if DuplicateHandle(src, HANDLE(l.handle as *mut c_void), GetCurrentProcess(), &mut probe, 0, false, DUPLICATE_SAME_ACCESS)
            .is_err()
        {
            return bail("the handle no longer exists".into());
        }
        // Use the worker with a timeout: if the value was reused for a blocking pipe, a synchronous name query would hang
        match NameQuerier::new().query(probe.0 as usize) {
            QueryResult::Ok(Some(now)) if now.to_lowercase() == l.nt_path => {
                let _ = CloseHandle(probe);
            }
            QueryResult::TimedOut => return bail("timed out checking the object name".into()), // don't close probe, the worker may still be using it
            QueryResult::Ok(other) => {
                let _ = CloseHandle(probe);
                return bail(format!("the handle now points to {}, no longer {}", other.as_deref().unwrap_or("<unnamed>"), l.nt_path));
            }
        }

        // Check 3: close it for real
        let mut sink = HANDLE::default();
        let ok =
            DuplicateHandle(src, HANDLE(l.handle as *mut c_void), GetCurrentProcess(), &mut sink, 0, false, DUPLICATE_CLOSE_SOURCE)
                .is_ok();
        if !sink.is_invalid() {
            let _ = CloseHandle(sink);
        }
        let _ = CloseHandle(src);
        ok
    }
}

/// Ends a process by pid. `expected_start` = creation time recorded by the scan (0 = no rights to read it
/// then, nothing to compare). Checked on **the same process handle**, so the process object can't change
/// between the check and the termination. Refuses: system-critical processes / explorer / unidentifiable
/// processes / creation time mismatched or unreadable.
pub fn terminate(pid: u32, expected_start: u64) -> bool {
    if is_critical_process(pid) {
        log::warn!("unlock: refusing to end system-critical process pid {pid}");
        return false;
    }
    // No name, no kill: letting "can't tell what it is" through would make the protected list pointless
    let Some(name) = process_basename(pid) else {
        log::warn!("unlock: can't identify pid {pid}, refusing to end it");
        return false;
    };
    if KILL_PROTECTED.contains(&name.to_ascii_lowercase().as_str()) {
        log::warn!("unlock: refusing to end protected process {name} (pid {pid})");
        return false;
    }
    enable_se_debug_privilege();
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        if expected_start != 0 && process_start_time_of(h) != Some(expected_start) {
            log::warn!("unlock: pid {pid} creation time mismatched or unreadable (PID may be reused), refusing to end it");
            let _ = CloseHandle(h);
            return false;
        }
        let ok = TerminateProcess(h, 1).is_ok();
        let _ = CloseHandle(h);
        ok
    }
}

// ── Internal helpers ────────────────────────────────────────────

/// Calls NtQuerySystemInformation with a growing buffer until the whole handle table fits.
fn snapshot_handles(nt_qsi: NtQuerySystemInformationFn) -> Option<Vec<u8>> {
    let mut size = 1024 * 1024;
    for _ in 0..8 {
        let mut buf = vec![0u8; size];
        let mut ret_len = 0u32;
        let st = unsafe { nt_qsi(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut ret_len) };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            size = (ret_len as usize).max(size * 2) + 256 * 1024; // the handle count keeps growing, leave headroom
            continue;
        }
        if st < 0 {
            return None;
        }
        return Some(buf);
    }
    None
}

fn query_type_name(nt_qo: NtQueryObjectFn, h: HANDLE) -> Option<String> {
    let mut buf = vec![0u8; 2048];
    let mut ret = 0u32;
    let st = unsafe { nt_qo(h, OBJECT_TYPE_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut ret) };
    if st < 0 {
        return None;
    }
    read_unicode_string(&buf)
}

enum QueryResult {
    Ok(Option<String>),
    TimedOut,
}

/// Reusable object-name querier: one worker thread runs NtQueryObject(name) requests in order, and the caller
/// waits for each result with a timeout. A timeout means that handle hung: the worker is discarded and the
/// caller creates a new one (the old worker is orphaned; acceptable for a one-off operation).
struct NameQuerier {
    req: std::sync::mpsc::Sender<usize>,
    resp: std::sync::mpsc::Receiver<Option<String>>,
}

impl NameQuerier {
    fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<usize>();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel::<Option<String>>();
        std::thread::spawn(move || {
            let Some(nt_qo) = nt_query_object() else { return };
            while let Ok(handle_val) = req_rx.recv() {
                if resp_tx.send(query_name_sync(nt_qo, handle_val)).is_err() {
                    break;
                }
            }
        });
        Self { req: req_tx, resp: resp_rx }
    }

    fn query(&self, handle_val: usize) -> QueryResult {
        if self.req.send(handle_val).is_err() {
            return QueryResult::Ok(None);
        }
        match self.resp.recv_timeout(NAME_TIMEOUT) {
            Ok(name) => QueryResult::Ok(name),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => QueryResult::TimedOut,
            Err(_) => QueryResult::Ok(None),
        }
    }
}

/// Gets the object name synchronously (runs on the worker thread, may hang).
fn query_name_sync(nt_qo: NtQueryObjectFn, handle_val: usize) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
    let h = HANDLE(handle_val as *mut c_void);
    // Pipes / consoles / character devices can't be files to unlock, and they're exactly the ones whose name query hangs
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return None;
    }
    let mut buf = vec![0u8; 4096];
    let mut ret = 0u32;
    let mut st = unsafe { nt_qo(h, OBJECT_NAME_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut ret) };
    if st == STATUS_INFO_LENGTH_MISMATCH && ret as usize > buf.len() {
        buf = vec![0u8; ret as usize];
        st = unsafe { nt_qo(h, OBJECT_NAME_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut ret) };
    }
    if st < 0 { None } else { read_unicode_string(&buf) }
}

/// NtQueryObject's Name / Type info both start with a UNICODE_STRING whose Buffer points into the rest of the
/// same allocation.
fn read_unicode_string(buf: &[u8]) -> Option<String> {
    if buf.len() < std::mem::size_of::<UnicodeString>() {
        return None;
    }
    let uni = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    if uni.buffer.is_null() || uni.length == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(uni.buffer, (uni.length / 2) as usize) };
    Some(String::from_utf16_lossy(slice))
}

/// Strips the `\\?\` / `\\?\UNC\` prefix, uses `\` as the separator and lowercases everything, so it compares
/// with QueryFullProcessImageNameW results.
fn normalize_win32_path(p: &str) -> String {
    let s = p.replace('/', "\\");
    let s = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s
    };
    s.to_lowercase()
}

/// DOS path (`C:\Users\...`) → NT device path (`\Device\HarddiskVolume3\Users\...`).
/// Fallback for when the target can't be opened; drive-letter paths only.
fn dos_to_nt_path(target: &Path) -> Option<String> {
    let mut s = target.to_string_lossy().replace('/', "\\");
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        s = rest.to_string();
    }
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' {
        return None;
    }
    let drive: Vec<u16> = s[..2].encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = [0u16; 1024];
    let len = unsafe { QueryDosDeviceW(PCWSTR(drive.as_ptr()), Some(&mut buf)) };
    if len == 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(format!("{}{}", String::from_utf16_lossy(&buf[..end]), &s[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("obunlock_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Drive-letter paths must convert to the \Device\... form, or nothing in the system-wide scan would match
    #[test]
    fn drive_path_maps_to_device() {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let nt = dos_to_nt_path(Path::new(&sys)).expect("a drive-letter path should convert");
        assert!(nt.starts_with(r"\Device\"), "{nt}");
        assert!(nt.to_lowercase().ends_with(r"\windows"), "{nt}");
        assert!(dos_to_nt_path(Path::new(r"\\wsl.localhost\Ubuntu\home")).is_none());
        assert!(dos_to_nt_path(Path::new("relative\\path")).is_none());
    }

    /// Folder matches must stop at a separator: c:\a must not swallow c:\ab
    #[test]
    fn hit_respects_separator() {
        assert!(hit(r"c:\a", true, r"c:\a"));
        assert!(hit(r"c:\a", true, r"c:\a\b.txt"));
        assert!(!hit(r"c:\a", true, r"c:\ab\b.txt"), "a sibling folder sharing the prefix doesn't count");
        assert!(!hit(r"c:\a.txt", false, r"c:\a.txt\x"), "a file target doesn't match sub-paths");
        assert_eq!(normalize_win32_path(r"\\?\UNC\srv\share\X"), r"\\srv\share\x");
        assert_eq!(normalize_win32_path(r"\\?\C:/Dir/A.TXT"), r"c:\dir\a.txt");
    }

    /// End to end: a child process holds a file inside the folder → it's found, and recorded under that folder (target 0)
    #[test]
    fn finds_child_process_holding_file() {
        let dir = tmp("scan");
        let file = dir.join("held.txt");
        std::fs::write(&file, b"x").unwrap();
        // powershell holds the file open exclusively and sleeps for 30 seconds
        let script = format!(
            "$f=[IO.File]::Open('{}','Open','ReadWrite','None'); Start-Sleep 30",
            file.display()
        );
        let mut child = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &script]).spawn().unwrap();
        let pid = child.id();
        let mut got = Vec::new();
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(250));
            got = find_lockers(std::slice::from_ref(&dir));
            if got.iter().any(|l| l.pid == pid && l.kind == LockKind::Handle) {
                break;
            }
        }
        let mine: Vec<&Locker> = got.iter().filter(|l| l.pid == pid).collect();
        assert!(mine.iter().any(|l| l.kind == LockKind::Handle && l.target == 0), "the child's handle should be found: {got:?}");
        // Unlock: after closing the handle the file can be deleted, and the process is still alive (it wasn't ended to get there)
        let h: Vec<Locker> = mine.into_iter().filter(|l| l.kind == LockKind::Handle).cloned().collect();
        assert!(release(&h) >= 1);
        assert!(std::fs::remove_file(&file).is_ok(), "should be deletable after closing the handle");
        assert!(child.try_wait().unwrap().is_none(), "only the handle was closed, the process is still running");
        let _ = child.kill();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn close_handle_rejects_zero_and_reused_pid() {
        let me = std::process::id();
        let l = |handle, start, nt: &str| Locker {
            pid: me,
            name: "t".into(),
            handle,
            start,
            target: 0,
            kind: LockKind::Handle,
            nt_path: nt.into(),
        };
        assert!(!close_handle(&l(0, 0, "x")), "handle 0 means nothing to close");
        assert!(!close_handle(&l(0x4, 1, r"\device\x")), "mismatched creation time = reused PID, must refuse");
    }

    /// Checks 2/3: open a file ourselves for a real handle; refuse on a path mismatch, close only on a match
    /// (covers both failing to close and closing the wrong one)
    #[test]
    fn close_handle_checks_path_identity() {
        use std::os::windows::io::AsRawHandle;
        let dir = tmp("close");
        let path = dir.join("target.bin");
        std::fs::write(&path, b"x").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let me = std::process::id();
        let nt = dos_to_nt_path(&path).unwrap().to_lowercase();
        let l = |nt_path: String| Locker {
            pid: me,
            name: "t".into(),
            handle: f.as_raw_handle() as usize,
            start: process_start_time(me).unwrap_or(0),
            target: 0,
            kind: LockKind::Handle,
            nt_path,
        };
        assert!(!close_handle(&l(format!("{nt}.other"))), "mismatched nt_path must be refused");
        assert!(close_handle(&l(nt)), "should close it when the path matches");
        std::mem::forget(f); // the handle was force-closed, don't let Drop close it again
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_refuses_system() {
        assert!(!terminate(4, 0));
        assert!(!terminate(0, 0));
    }
}
