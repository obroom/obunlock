# obunlock

[English](README.md) · **简体中文**

Windows 文件解锁引擎（Rust）：查出谁锁着文件或文件夹，解锁（关句柄或结束进程），强制删除，
或者登记重启后删除。

[ObCommander](https://obcommander.com)、[HotKit](https://hotkit.app) 和
[ObCleaner](https://github.com/obroom/obcleaner) 的解锁功能都用的是它。
这个 crate 只有引擎，没有界面，弹窗、确认、提示由宿主程序自己做。

## 功能

**查占用**：四路互补的检测并行跑，总耗时约等于最慢的那一路。

| # | 方式 | 能找到 | 解锁手段 |
|---|------|--------|---------|
| 1 | 全系统句柄扫描（`NtQuerySystemInformation` + `NtQueryObject`） | 打开着的文件句柄 | 关句柄 |
| 2 | 映射扫描 | 运行中的 exe、已加载的 DLL、内存映射文件（这些是 Section，不是句柄） | 结束进程 |
| 3 | 文件侧反查（`FileProcessIdsUsingFileInformation`） | 第 1 路打不开的进程（受保护进程、提权进程、System） | 结束进程 |
| 4 | Restart Manager | 系统官方的“文件正在使用” | 结束进程 |

目标是文件夹时，里面任何一项被占用都算。

**删除**

- 用 POSIX 语义删除，带 `FORCE_IMAGE_SECTION_CHECK`（需 Windows 10 1809 及以上），运行中的 exe
  和已加载的 DLL 也能马上把名字摘掉。不支持时退回标准库。
- 文件和各层目录都并行删。出错不中断：能删的都删掉，最后只剩删不掉的那些路径。
- 支持 `\\?\` 长路径。联接点和符号链接只删链接本身，不会进到里面去。
- 重启后删除（`MoveFileExW` + `MOVEFILE_DELAY_UNTIL_REBOOT`）。未提权时会以管理员身份重新拉起
  宿主 exe 来登记。

## 安全底线

关别的进程的句柄、结束进程都有风险，所以引擎的策略偏保守：

- **关句柄前过三道闸**：先核对进程创建时间和扫描时一致（防 PID 被重用），再核对句柄现在仍指向
  同一个路径（防句柄值被重用），两道都过了才真关。
- **结束进程前**，在同一个进程句柄上核对身份。认不出是谁就不结束。
- **系统关键进程只展示、不动手**（System、csrss、lsass、带 `BreakOnTermination` 标记的等），
  动了就蓝屏。`explorer.exe` 也不结束。
- **危险路径一律拒绝**：盘根、`%SystemRoot%`、Program Files、ProgramData、Users 目录和当前用户
  目录本身。这些目录下面的子目录可以删。

即便有这些检查，背着程序关掉它的句柄仍可能让它崩溃或丢掉未保存的数据。调用 `release` 或
`kill_all` 之前，务必先让用户确认。

## 用法

```toml
[dependencies]
obunlock = { git = "https://github.com/obroom/obunlock" }
```

```rust
use std::path::PathBuf;

fn main() {
    // 必须放在 main 最前面（单实例检查之前）：接住提权后重新拉起的 --delete-on-reboot 助手
    if let Some(code) = obunlock::run_reboot_delete_helper() {
        std::process::exit(code);
    }

    let targets = vec![PathBuf::from(r"C:\some\locked\folder")];

    // 要扫全系统，耗时几百毫秒到几秒，不要在 UI 线程里调
    let lockers = obunlock::find_lockers(&targets);
    for l in &lockers {
        println!("{} (pid {}) {:?}, 会结束进程: {}", l.name, l.pid, l.kind, obunlock::will_kill(l));
    }

    // 用户确认之后再解锁
    obunlock::release(&lockers);

    match obunlock::force_delete(&targets[0]) {
        Ok(stats) => println!("删了 {} 个文件, {} 个目录", stats.files, stats.dirs),
        Err(e) => {
            println!("还是删不掉: {e:?}");
            // 未提权时会弹 UAC。返回 None 表示用户拒绝了
            obunlock::schedule_reboot_delete(&targets);
        }
    }
}
```

日志走 [`log`](https://crates.io/crates/log) 门面，宿主不装 logger 就什么都不输出。

想看某个路径扫出来的结果，可以在不同权限下分别运行，对比差异：

```
cargo run --release --example scan -- <路径>...
```

## 环境要求

- Windows 10 及以上（x64）。没有管理员权限时，提权进程和受保护进程里的占用照样能查出来，但解不开。
- Rust 1.85 及以上（edition 2024）。

## 许可证

[MIT](LICENSE)
