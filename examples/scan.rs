//! Troubleshooting: scan for lockers once and print each record (when the same target gives different
//! results in different apps, run this at different privilege levels to compare).
//!   cargo run --release --example scan -- <path>...
fn main() {
    let paths: Vec<std::path::PathBuf> = std::env::args().skip(1).map(Into::into).collect();
    println!("elevated = {}", obunlock::is_elevated());
    let t = std::time::Instant::now();
    let mut ls = obunlock::find_lockers(&paths);
    ls.sort_by_key(|l| (l.pid, l.kind as u8));
    for l in &ls {
        println!("{:>6} {:<24} {:?} target#{} handle={:#x} {}", l.pid, l.name, l.kind, l.target, l.handle, l.nt_path);
    }
    let mut pids: Vec<u32> = ls.iter().map(|l| l.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    println!("{} records, {} processes, {:?}", ls.len(), pids.len(), t.elapsed());
}
