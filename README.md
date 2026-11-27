# obunlock

**English** · [简体中文](README.zh-CN.md)

A Windows file-unlocking engine in Rust: find out who is locking a file or folder, release it
(close the handle or end the process), force-delete it, or schedule it for deletion on reboot.

It powers the unlock feature in [ObCommander](https://obcommander.com), [HotKit](https://hotkit.app) and
[ObCleaner](https://github.com/obroom/obcleaner).
The crate is engine only — no UI. Confirmations and prompts belong to the host app.

## What it does

**Finding lockers** — four complementary scans run in parallel (total time ≈ the slowest one):

| # | Method | Finds | Release by |
|---|--------|-------|-----------|
| 1 | System-wide handle scan (`NtQuerySystemInformation` + `NtQueryObject`) | Open file handles | Closing the handle |
| 2 | Mapped-image scan | Running exe / loaded DLL / memory-mapped files (sections, not handles) | Ending the process |
| 3 | File-side lookup (`FileProcessIdsUsingFileInformation`) | Processes scan 1 can't open (protected, elevated, System) | Ending the process |
| 4 | Restart Manager | The official "file in use" answer | Ending the process |

For a folder, anything locked inside it counts.

**Deleting**

- POSIX-semantics delete with `FORCE_IMAGE_SECTION_CHECK` (Windows 10 1809+), so the name of a
  running exe or loaded DLL is removed right away. Falls back to the standard library elsewhere.
- Files and directory levels are deleted in parallel. Errors don't stop the run: everything
  deletable is deleted, and only the failing paths remain.
- `\\?\` long paths. Junctions and symlinks are removed as links and never followed.
- Delete on reboot (`MoveFileExW` + `MOVEFILE_DELAY_UNTIL_REBOOT`). When not elevated, it
  relaunches the host exe as admin to register the paths.

## Safety rules

Closing another process's handle or ending a process is dangerous, so the engine is deliberately
conservative:

- **Three checks before closing a handle**: the process creation time must match the scan (guards
  against PID reuse) → the handle must still point to the same path (guards against handle-value
  reuse) → only then is it closed.
- **Process identity is checked before ending a process**, on the same process handle. If the
  process can't be identified, it is not ended.
- **System-critical processes are reported but never touched** (System, csrss, lsass, anything
  with `BreakOnTermination`, …). Touching them means a blue screen. `explorer.exe` is never ended.
- **Dangerous paths are refused**: drive roots, `%SystemRoot%`, Program Files, ProgramData, the
  Users folder and the user profile folder itself. Their subfolders are allowed.

Even with these checks, closing a handle behind a program's back can still crash that program or
lose its unsaved data. Ask the user before you call `release` / `kill_all`.

## Usage

```toml
[dependencies]
obunlock = { git = "https://github.com/obroom/obunlock" }
```

```rust
use std::path::PathBuf;

fn main() {
    // Must be the first thing in main (before any single-instance check):
    // handles the elevated `--delete-on-reboot` helper relaunch.
    if let Some(code) = obunlock::run_reboot_delete_helper() {
        std::process::exit(code);
    }

    let targets = vec![PathBuf::from(r"C:\some\locked\folder")];

    // Scans the whole system: takes hundreds of ms to a few seconds. Call it off the UI thread.
    let lockers = obunlock::find_lockers(&targets);
    for l in &lockers {
        println!("{} (pid {}) {:?}, ends process: {}", l.name, l.pid, l.kind, obunlock::will_kill(l));
    }

    // After the user confirms:
    obunlock::release(&lockers);

    match obunlock::force_delete(&targets[0]) {
        Ok(stats) => println!("deleted {} files, {} dirs", stats.files, stats.dirs),
        Err(e) => {
            println!("still locked: {e:?}");
            // Shows a UAC prompt when not elevated. None = the user declined it.
            obunlock::schedule_reboot_delete(&targets);
        }
    }
}
```

Logging uses the [`log`](https://crates.io/crates/log) facade and prints nothing unless the host
installs a logger.

To see what the scan finds for a path, run it at different privilege levels:

```
cargo run --release --example scan -- <path>...
```

## Requirements

- Windows 10 or later (x64). Without admin rights, lockers in elevated or protected processes are
  still detected but can't be released.
- Rust 1.85+ (edition 2024).

## License

[MIT](LICENSE)
