//! msu-inspector 進入點（Task 16 接上 GUI）。

fn main() {
    std::process::exit(msu_inspector::cli::run(std::env::args_os().collect()));
}
