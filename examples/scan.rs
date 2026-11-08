//! 排查用: 扫一遍占用, 逐条打印 (同一目标在 obcmd / hotkit 里结果不一样时, 用它在不同权限下对比)。
//!   cargo run --release --example scan -- <路径>...
fn main() {
    let paths: Vec<std::path::PathBuf> = std::env::args().skip(1).map(Into::into).collect();
    println!("elevated = {}", ob_unlock::is_elevated());
    let t = std::time::Instant::now();
    let mut ls = ob_unlock::find_lockers(&paths);
    ls.sort_by_key(|l| (l.pid, l.kind as u8));
    for l in &ls {
        println!("{:>6} {:<24} {:?} target#{} handle={:#x} {}", l.pid, l.name, l.kind, l.target, l.handle, l.nt_path);
    }
    let mut pids: Vec<u32> = ls.iter().map(|l| l.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    println!("{} 条, {} 个进程, {:?}", ls.len(), pids.len(), t.elapsed());
}
