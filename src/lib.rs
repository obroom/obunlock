//! File-unlocking engine (in the vein of IObit Unlocker), shared by ObCommander, HotKit and ObCleaner.
//! Engine only, no UI: dialogs, confirmations and messages belong to the host app. Logging goes
//! through the `log` facade and prints nothing unless the host installs a logger.
//!
//! - [`find_lockers`]: who is locking these files / folders (four scans in parallel, see `scan.rs`)
//! - [`release`] / [`close_handle`] / [`terminate`]: unlock: close the handle, or end the process if there is none
//! - [`force_delete`] / [`schedule_reboot_delete`]: force delete, and if that still fails, delete on reboot
//!
//! Safety rules:
//! - Three checks before closing a handle: process creation time → the path the handle points to now →
//!   only then close it (guards against PID / handle-value reuse)
//! - Before ending a process, its creation time is checked on the same process handle; a process that
//!   can't be identified is not ended
//! - System-critical processes (System / csrss / lsass / anything with BreakOnTermination) are shown but
//!   never touched: touching them means a blue screen
//! - Drive roots / Windows / Program Files / the user profile folder itself can't be deleted as a whole

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
