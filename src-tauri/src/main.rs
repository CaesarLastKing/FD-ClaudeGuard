// 在 Windows Release 构建中隐藏默认控制台黑窗
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    fd_claude_guard_lib::run();
}
