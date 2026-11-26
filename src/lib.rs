//! 文件解锁引擎 (IObit Unlocker 同类), obcmd、hotkit、obcleaner 共用。只有引擎, 没有界面 ——
//! 弹窗 / 确认 / 提示由各自程序做。日志走 `log` 门面, 宿主不装 logger 就不出。
//!
//! - [`find_lockers`]: 谁锁着这些文件 / 文件夹 (四路并行检测, 见 `scan.rs`)
//! - [`release`] / [`close_handle`] / [`terminate`]: 解锁 —— 关句柄, 关不了的结束进程
//! - [`force_delete`] / [`schedule_reboot_delete`]: 强删, 还删不掉就登记重启后删除
//!
//! 安全底线 (两边合并时取严的那一边):
//! - 关句柄前三道闸: 进程创建时间 → 句柄现在指向的路径 → 才真关 (防 PID / 句柄值重用误伤)
//! - 结束进程前在同一个进程句柄上核对创建时间; 认不出是谁就不杀
//! - 系统关键进程 (System / csrss / lsass / 带 BreakOnTermination 的) 只展示不动手, 动了就蓝屏
//! - 盘根 / Windows / Program Files / 用户目录这些目录本身不让整个删

mod delete;
mod process;
mod scan;

pub use delete::{
    DeleteError, DeleteStats, force_delete, is_elevated, is_protected_path, run_reboot_delete_helper,
    schedule_delete_on_reboot, schedule_reboot_delete, REBOOT_DELETE_ARG,
};
pub use process::{
    KILL_PROTECTED, enable_se_debug_privilege, is_critical_process, process_basename, process_image_path,
    process_start_time, process_start_time_of,
};
pub use scan::{LockKind, Locker, close_handle, find_lockers, kill_all, release, terminate, will_kill};
