//! 找出"谁锁着这个文件/文件夹", 以及解锁 (关句柄 / 结束进程)。
//!
//! 四路互补, 并行跑 (总耗时 ≈ 最慢的一路):
//! 1. 全系统句柄扫描 (`Handle`, 可关句柄): `NtQuerySystemInformation(SystemExtendedHandleInformation)`
//!    → 逐个 `DuplicateHandle` 进本进程 → `NtQueryObject` 取类型 (筛 File) 和对象名 (NT 设备路径) → 比对。
//! 2. 映射扫描 (`Image`): 进程主 exe / 已加载 DLL / 内存映射的数据文件在目标内 —— 那是 Section 不是
//!    File 句柄, 1 看不到 (运行中程序的文件夹删不掉就是这个)。
//! 3. 文件侧反查 (`InUse`, FileProcessIdsUsingFileInformation): 问文件"谁开着你", 能看到 1 打不开的
//!    进程 (受保护进程 / 未提权时的管理员进程 / System)。文件夹遍历内部条目 (有上限)。
//! 4. Restart Manager (`InUse`): 官方"文件正在使用"机制, 只对文件做。
//!
//! ## 挂死与速度 (合并两边的处理)
//! - `NtQueryObject(名字)` 对命名管道等句柄会永久挂起: 先 `GetFileType` 只给磁盘文件查名字,
//!   再放 worker 线程 + 超时, 挂住就弃线程换新的 (一次扫描最多泄漏个位数线程/句柄)。
//!   **不要按 GrantedAccess==0x0012019F 跳过**: 那正是 GENERIC_READ|GENERIC_WRITE 打开文件的掩码,
//!   跳过它等于漏掉所有读写打开的文件 (Office / 编辑器 / 数据库), 两边都实测漏检过。
//! - 首次识别出 File 类型的 ObjectTypeIndex 后缓存, 非 File 句柄连 Duplicate 都省了。
//! - 同一内核文件对象常被许多句柄共享 (系统 DLL 几十个进程开着), 名字按对象指针缓存, 只查一次。
//! - 句柄扫描总预算 [`BUDGET`], 极端环境到点就返回已找到的。

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

/// 一条占用记录: 某进程以某种方式锁着第 `target` 个目标。同一进程可能有多条。
#[derive(Debug, Clone)]
pub struct Locker {
    pub pid: u32,
    pub name: String,
    /// **源进程里**的句柄值 (`kind == Handle` 才非 0), 供强制关闭用。
    pub handle: usize,
    /// 进程创建时间 (0 = 没查到)。动手前重查比对, 防 PID 重用误伤无辜新进程。
    pub start: u64,
    /// 命中的目标下标 (`find_lockers` 入参的索引)。嵌套多选时只记第一个命中的。
    pub target: usize,
    pub kind: LockKind,
    /// 扫描当时这个句柄指向的 NT 路径 (小写, 只 `Handle` 有)。关之前再核对一遍 —— 从扫描到用户点确定
    /// 隔着一个窗口, 目标进程完全可能关掉句柄、内核又把同一个值分给别的文件, 不核对就会静默关错。
    pub nt_path: String,
}

/// 占用来源, 决定解锁手段, 也决定去重: 同一 (pid, 目标) 已有 Handle / Image 时 InUse 是冗余的 ——
/// 留着会让「解锁」把只需关句柄的进程也结束掉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    /// 句柄扫描命中, 句柄可关。
    Handle,
    /// 进程把目标映射进了内存 (主 exe / DLL / 映射的数据文件), 没有可关的句柄, 只能结束进程。
    Image,
    /// 文件系统 / Restart Manager 说它在用, 句柄扫描看不到 (受保护 / 权限不够), 只能结束进程。
    InUse,
}

/// 句柄扫描总预算: 到点就返回已找到的。一次性操作, 用户在等, 够用了。
const BUDGET: Duration = Duration::from_secs(12);
/// 单个句柄查名超时。磁盘文件查名是微秒级, 管道已被 GetFileType 筛掉, 这是兜底。
const NAME_TIMEOUT: Duration = Duration::from_millis(80);
/// 文件侧反查时文件夹内部最多问这么多条 / 花这么久 (node_modules 逐个打开太慢, 只是兜底)。
const IN_USE_MAX_ENTRIES: usize = 20_000;
const IN_USE_BUDGET: Duration = Duration::from_millis(1500);

// ── ntdll 动态绑定 ──────────────────────────────────────────────

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

// ── 内核结构 (x64 布局) ─────────────────────────────────────────

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
    // handles: [SystemHandleTableEntryInfoEx; number_of_handles] 紧随其后
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

// ── 目标 ─────────────────────────────────────────────────────────

/// 一个待比对的目标。`nt` 跟 NtQueryObject / GetMappedFileName 同形态 (`\device\harddiskvolume3\...`),
/// `dos` 跟进程镜像路径同形态 (`c:\...`), 都已小写、去尾部 `\`。两者都取**最终路径**
/// (GetFinalPathNameByHandle): 8.3 短名 / subst 盘 / 挂载点会被展开成内核实际记录的那份,
/// 网络路径 (`\device\mup\...`) 也能比。打不开时退回字符串换算。
struct Spec {
    nt: String,
    dos: String,
    is_dir: bool,
    idx: usize,
}

impl Spec {
    /// `name` (已小写) 命中: 完全相等, 或目标是文件夹且 `name` 在它里面。
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

/// 只要属性访问权打开 (不受共享模式限制, 被独占锁住也打得开), 取最终路径。
/// `nt=true` 返回 `\Device\...` 形态, 否则 DOS 形态 (带 `\\?\`)。
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

/// 只带 FILE_READ_ATTRIBUTES 打开文件或目录 (BACKUP_SEMANTICS 允许开目录)。
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

// ── 公开 API ─────────────────────────────────────────────────────

/// 找出锁住任意目标 (文件或文件夹) 的所有进程。目标是文件夹时, 里面任意子项被占用也算
/// (删不掉的常见根因)。结果按 (pid, 目标) 去重: 已有 Handle / Image 的不再留 InUse。
///
/// **必须在后台线程调** —— 全系统枚举几百 ms 到几秒。失败 / 无占用返回空。
pub fn find_lockers(targets: &[PathBuf]) -> Vec<Locker> {
    enable_se_debug_privilege();
    let t0 = Instant::now();
    // symlink_metadata: 联接点 / 链接本身不算文件夹 (删的也只是链接)
    let targets: Vec<(PathBuf, bool)> =
        targets.iter().map(|p| (p.clone(), std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))).collect();
    let specs = build_specs(&targets);
    if specs.is_empty() {
        return Vec::new();
    }

    let specs = &specs;
    let targets = &targets;
    let (mut lockers, t_handles, t_images) = std::thread::scope(|sc| {
        let timed = |f: fn(&[Spec]) -> Vec<Locker>| {
            move || {
                let t = Instant::now();
                (f(specs), t.elapsed())
            }
        };
        let handles = sc.spawn(timed(handle_lockers));
        let images = sc.spawn(timed(image_lockers));
        let mut out = in_use_lockers(targets);
        out.extend(restart_manager_lockers(targets));
        let (h, th) = handles.join().unwrap_or_default();
        let (i, ti) = images.join().unwrap_or_default();
        out.extend(h);
        out.extend(i);
        (out, th, ti)
    });

    let strong: std::collections::HashSet<(u32, usize)> =
        lockers.iter().filter(|l| l.kind != LockKind::InUse).map(|l| (l.pid, l.target)).collect();
    let mut seen_weak = std::collections::HashSet::new();
    lockers.retain(|l| l.kind != LockKind::InUse || (!strong.contains(&(l.pid, l.target)) && seen_weak.insert((l.pid, l.target))));

    for l in &lockers {
        log::info!("unlock: target#{} locked by {} (pid {}, {:?}, handle {:#x})", l.target, l.name, l.pid, l.kind, l.handle);
    }
    log::info!(
        "unlock: scan done, {} targets, {} records ({}ms: handles {}ms, images {}ms)",
        targets.len(),
        lockers.len(),
        t0.elapsed().as_millis(),
        t_handles.as_millis(),
        t_images.as_millis(),
    );
    lockers
}

/// 这条占用的解锁方式是结束进程, 而且这个进程允许结束 —— 点「解锁」前要不要先确认"将结束进程"。
pub fn will_kill(l: &Locker) -> bool {
    l.handle == 0 && !is_critical_process(l.pid)
}

/// 解锁: 能关的句柄关掉; 没有句柄可关的 (映射 / 只知道在用) 结束进程 (调用方已确认过)。
/// 系统关键进程两样都不碰。返回解除的处数。
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

/// 强制模式: 每个占用进程都结束 (同样跳过关键进程 / explorer)。返回结束了几个。
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

// ── 第 1 路: 句柄扫描 ───────────────────────────────────────────

/// 进程名 / 创建时间按 pid 缓存 (几路扫描都要)。
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
    // 内核对象指针 → 对象名 (None = 无名 / 查不到 / 不是磁盘文件)
    let mut obj_names: std::collections::HashMap<usize, Option<String>> = std::collections::HashMap::new();
    let started = Instant::now();

    let mut record = |name: &str, entry: &SystemHandleTableEntryInfoEx, pid: u32, lockers: &mut Vec<Locker>| {
        if let Some(s) = specs.iter().find(|s| s.hit(name, true)) {
            lockers.push(info.locker(pid, entry.handle_value, s.idx, LockKind::Handle, name));
        }
    };

    for i in 0..count {
        if started.elapsed() > BUDGET {
            log::warn!("unlock: 句柄扫描超预算, 已查 {i}/{count}, 提前返回");
            break;
        }
        let entry = unsafe { &*entries_ptr.add(i) };
        let pid = entry.unique_process_id as u32;
        // System (pid 4) 不跳过: 驱动 / SMB 共享代开的文件句柄挂在它名下。只展示, 不会去关 (见 close_handle)
        if pid == our_pid || pid == 0 {
            continue;
        }
        if file_type_index.is_some_and(|idx| entry.object_type_index != idx) {
            continue;
        }
        if let Some(cached) = obj_names.get(&(entry.object as usize)) {
            if let Some(name) = cached {
                record(name, entry, pid, &mut lockers);
            }
            continue;
        }

        let src = *proc_cache
            .entry(pid)
            .or_insert_with(|| unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) }.unwrap_or_default());
        if src.is_invalid() {
            continue; // 打不开 (权限 / 已退) → 第 3 路兜底
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
                obj_names.insert(entry.object as usize, name);
                unsafe {
                    let _ = CloseHandle(dup);
                }
            }
            QueryResult::TimedOut => {
                // 卡死: 记成无名 (同对象别再卡一次), 弃 dup (旧 worker 可能还在用它), 换新 worker
                obj_names.insert(entry.object as usize, None);
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

// ── 第 2 路: 映射扫描 ───────────────────────────────────────────

/// 逐段 `VirtualQueryEx` 遍历对方地址空间, 每个 MEM_IMAGE / MEM_MAPPED 分配 (按 AllocationBase 只查一次)
/// 用 `GetMappedFileNameW` 取 NT 路径比对。打不开内存的进程退回只比主 exe 路径。
/// 同一进程可能既开着句柄又映射着目标: Handle 负责关句柄, Image 负责结束进程, 不能跨 kind 去重。
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
            continue; // System 没有用户态映射
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

// ── 第 3 路: 文件侧反查 ─────────────────────────────────────────

fn in_use_lockers(targets: &[(PathBuf, bool)]) -> Vec<Locker> {
    let Some(nt_qif) = nt_query_information_file() else {
        return Vec::new();
    };
    let our_pid = unsafe { GetCurrentProcessId() };
    let deadline = Instant::now() + IN_USE_BUDGET;
    let mut info = ProcInfoCache::default();
    let mut found: std::collections::HashSet<(u32, usize)> = std::collections::HashSet::new();
    let mut lockers = Vec::new();
    let mut entries = 0usize;
    let mut ask = |p: &Path, idx: usize, lockers: &mut Vec<Locker>| {
        for pid in pids_using(nt_qif, p) {
            if pid != our_pid && pid != 0 && found.insert((pid, idx)) {
                lockers.push(info.locker(pid, 0, idx, LockKind::InUse, ""));
            }
        }
    };

    for (idx, (root, is_dir)) in targets.iter().enumerate() {
        let mut stack = vec![root.clone()];
        while let Some(p) = stack.pop() {
            entries += 1;
            ask(&p, idx, &mut lockers);
            if !*is_dir || entries >= IN_USE_MAX_ENTRIES || Instant::now() >= deadline {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&p) else { continue };
            for e in rd.flatten() {
                match e.file_type() {
                    Ok(ft) if ft.is_symlink() => {} // 联接点 / 链接指向的东西不在这个文件夹里
                    Ok(ft) if ft.is_dir() => stack.push(e.path()),
                    Ok(_) => {
                        entries += 1;
                        ask(&e.path(), idx, &mut lockers);
                    }
                    Err(_) => {}
                }
            }
        }
    }
    if entries >= IN_USE_MAX_ENTRIES || Instant::now() >= deadline {
        log::info!("unlock: in-use walk stopped early after {entries} entries");
    }
    lockers
}

/// 开着 `p` 的进程 pid (含本进程自己 —— 查询时我们也开着它)。
fn pids_using(nt_qif: NtQueryInformationFileFn, p: &Path) -> Vec<u32> {
    let Some(h) = open_attr_only(p) else { return Vec::new() };
    // FILE_PROCESS_IDS_USING_FILE_INFORMATION: ULONG 计数, 对齐后接 ULONG_PTR[]
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

// ── 第 4 路: Restart Manager ───────────────────────────────────

/// 只对文件做 (目录不能被加载为模块, RM 也不递归)。每个文件单独一个会话 —— RmGetList 不区分
/// 命中的是哪个资源, 合在一起就没法按文件归属。
fn restart_manager_lockers(targets: &[(PathBuf, bool)]) -> Vec<Locker> {
    use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources, RmStartSession,
    };
    use windows::core::PWSTR;

    let our_pid = unsafe { GetCurrentProcessId() };
    let mut lockers = Vec::new();
    for (idx, (path, is_dir)) in targets.iter().enumerate() {
        if *is_dir {
            continue;
        }
        let path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let mut session: u32 = 0;
        let mut key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        if unsafe { RmStartSession(&mut session, None, PWSTR(key.as_mut_ptr())) } != ERROR_SUCCESS {
            continue;
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
    }
    lockers
}

// ── 解锁 ─────────────────────────────────────────────────────────

/// 强制关闭 `l` 记录的那个句柄 (DuplicateHandle + DUPLICATE_CLOSE_SOURCE 在源进程里关掉)。
///
/// **高危**: 目标程序不知道句柄没了, 继续用会崩 / 坏数据。调用方须已确认。
/// 动手前三道闸: 进程创建时间对得上 → 先只读复制一份看它现在指向哪儿 → 路径跟扫描时一致才真关。
/// 系统关键进程一律拒绝: System 的句柄表就是内核句柄表, 关掉驱动在用的句柄会蓝屏。
pub fn close_handle(l: &Locker) -> bool {
    if l.handle == 0 || l.nt_path.is_empty() {
        return false; // 没有可关的句柄 (映射 / 只知道在用), 只能结束进程
    }
    if is_critical_process(l.pid) {
        log::warn!("unlock: 拒绝在系统关键进程 {} (pid {}) 里关句柄", l.name, l.pid);
        return false;
    }
    enable_se_debug_privilege();
    unsafe {
        let Ok(src) = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, l.pid) else {
            return false;
        };
        let bail = |why: String| {
            log::warn!("unlock: 放弃关闭 {} (pid {}) 的句柄 —— {why}", l.name, l.pid);
            let _ = CloseHandle(src);
            false
        };

        // 闸 1: PID 没被重用
        if l.start != 0 && process_start_time_of(src).is_some_and(|now| now != l.start) {
            return bail("创建时间与扫描时不符, PID 已被重用".into());
        }

        // 闸 2: 复制一份**不带** CLOSE_SOURCE 的, 看这个句柄值现在指向什么
        let mut probe = HANDLE::default();
        if DuplicateHandle(src, HANDLE(l.handle as *mut c_void), GetCurrentProcess(), &mut probe, 0, false, DUPLICATE_SAME_ACCESS)
            .is_err()
        {
            return bail("句柄已不存在".into());
        }
        // 走带超时的 worker: 万一这个值被重用成了阻塞管道, 同步查名会挂死
        match NameQuerier::new().query(probe.0 as usize) {
            QueryResult::Ok(Some(now)) if now.to_lowercase() == l.nt_path => {
                let _ = CloseHandle(probe);
            }
            QueryResult::TimedOut => return bail("核对对象名超时".into()), // probe 不能关, worker 可能还在用
            QueryResult::Ok(other) => {
                let _ = CloseHandle(probe);
                return bail(format!("句柄已改指向 {}, 不再是 {}", other.as_deref().unwrap_or("<无名>"), l.nt_path));
            }
        }

        // 闸 3: 真关
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

/// 按 pid 结束进程。`expected_start` = 扫描时记的创建时间 (0 = 当时就没权限查, 没得比)。
/// 在**同一个进程句柄**上核对, 查验与终止之间进程对象不会换人。
/// 拒绝: 系统关键进程 / explorer / 认不出是谁 / 创建时间对不上或查不到。
pub fn terminate(pid: u32, expected_start: u64) -> bool {
    if is_critical_process(pid) {
        log::warn!("unlock: 拒绝结束系统关键进程 pid {pid}");
        return false;
    }
    // 名字查不到就不杀: "认不出是谁"反而放行, 保护名单就形同虚设
    let Some(name) = process_basename(pid) else {
        log::warn!("unlock: 认不出 pid {pid} 是什么进程, 拒绝结束");
        return false;
    };
    if KILL_PROTECTED.contains(&name.to_ascii_lowercase().as_str()) {
        log::warn!("unlock: 拒绝结束受保护进程 {name} (pid {pid})");
        return false;
    }
    enable_se_debug_privilege();
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        if expected_start != 0 && process_start_time_of(h) != Some(expected_start) {
            log::warn!("unlock: pid {pid} 创建时间对不上或查不到 (PID 可能已重用), 拒绝结束");
            let _ = CloseHandle(h);
            return false;
        }
        let ok = TerminateProcess(h, 1).is_ok();
        let _ = CloseHandle(h);
        ok
    }
}

// ── 内部 helper ─────────────────────────────────────────────────

/// 反复扩容调用 NtQuerySystemInformation 直到装得下整张句柄表。
fn snapshot_handles(nt_qsi: NtQuerySystemInformationFn) -> Option<Vec<u8>> {
    let mut size = 1024 * 1024;
    for _ in 0..8 {
        let mut buf = vec![0u8; size];
        let mut ret_len = 0u32;
        let st = unsafe { nt_qsi(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut ret_len) };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            size = (ret_len as usize).max(size * 2) + 256 * 1024; // 句柄数在涨, 留余量
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

/// 复用型对象名查询器: 一个 worker 线程顺序处理 NtQueryObject(名字), 调用方带超时收结果。
/// 超时 = 该句柄挂死, worker 作废, 调用方换新的 (旧 worker 成孤儿, 一次性操作可接受)。
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

/// 同步取对象名 (在 worker 线程里跑, 可能挂死)。
fn query_name_sync(nt_qo: NtQueryObjectFn, handle_val: usize) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};
    let h = HANDLE(handle_val as *mut c_void);
    // 管道 / 控制台 / 字符设备不可能是要解锁的文件, 而且正是查名挂死的那批
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

/// NtQueryObject 的 Name / Type 信息都以 UNICODE_STRING 打头, Buffer 指向同一分配的后半段。
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

/// 去 `\\?\` / `\\?\UNC\` 前缀, 分隔符统一 `\`, 全小写 —— 跟 QueryFullProcessImageNameW 的结果可比。
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

/// DOS 路径 (`C:\Users\...`) → NT 设备路径 (`\Device\HarddiskVolume3\Users\...`)。
/// 目标打不开时的退路, 只认盘符形态。
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
        let d = std::env::temp_dir().join(format!("ob_unlock_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 盘符路径要能转成 \Device\... 形态, 否则全系统扫描一条都对不上
    #[test]
    fn drive_path_maps_to_device() {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let nt = dos_to_nt_path(Path::new(&sys)).expect("盘符路径应该能转");
        assert!(nt.starts_with(r"\Device\"), "{nt}");
        assert!(nt.to_lowercase().ends_with(r"\windows"), "{nt}");
        assert!(dos_to_nt_path(Path::new(r"\\wsl.localhost\Ubuntu\home")).is_none());
        assert!(dos_to_nt_path(Path::new("relative\\path")).is_none());
    }

    /// 文件夹命中要卡在分隔符上: c:\a 不能吃掉 c:\ab
    #[test]
    fn hit_respects_separator() {
        assert!(hit(r"c:\a", true, r"c:\a"));
        assert!(hit(r"c:\a", true, r"c:\a\b.txt"));
        assert!(!hit(r"c:\a", true, r"c:\ab\b.txt"), "同前缀的兄弟目录不算");
        assert!(!hit(r"c:\a.txt", false, r"c:\a.txt\x"), "文件目标不吃子路径");
        assert_eq!(normalize_win32_path(r"\\?\UNC\srv\share\X"), r"\\srv\share\x");
        assert_eq!(normalize_win32_path(r"\\?\C:/Dir/A.TXT"), r"c:\dir\a.txt");
    }

    /// 端到端: 子进程开着文件夹里的文件 → 扫得到, 而且记在那个文件夹 (target 0) 名下
    #[test]
    fn finds_child_process_holding_file() {
        let dir = tmp("scan");
        let file = dir.join("held.txt");
        std::fs::write(&file, b"x").unwrap();
        // powershell 以独占方式开着文件睡 30 秒
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
        assert!(mine.iter().any(|l| l.kind == LockKind::Handle && l.target == 0), "应扫到子进程的句柄: {got:?}");
        // 解锁: 关掉句柄后文件就能删了, 进程还活着 (不是靠结束进程删的)
        let h: Vec<Locker> = mine.into_iter().filter(|l| l.kind == LockKind::Handle).cloned().collect();
        assert!(release(&h) >= 1);
        assert!(std::fs::remove_file(&file).is_ok(), "关句柄后应能删");
        assert!(child.try_wait().unwrap().is_none(), "只关句柄, 进程还在");
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
        assert!(!close_handle(&l(0, 0, "x")), "handle 0 无句柄可关");
        assert!(!close_handle(&l(0x4, 1, r"\device\x")), "创建时间对不上 = PID 已重用, 必须拒绝");
    }

    /// 闸 2/3: 自己开个文件拿真句柄, 路径对不上要拒绝、对得上才真关 (盯着漏关和误关两个方向)
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
        assert!(!close_handle(&l(format!("{nt}.other"))), "nt_path 对不上必须拒绝");
        assert!(close_handle(&l(nt)), "路径一致时应真关掉");
        std::mem::forget(f); // 句柄已被强关, 别让 Drop 再关一次
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn terminate_refuses_system() {
        assert!(!terminate(4, 0));
        assert!(!terminate(0, 0));
    }
}
