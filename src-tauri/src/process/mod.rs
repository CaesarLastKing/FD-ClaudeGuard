use crate::logger;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// 每次拦截 Claude 后台复活进程后自动顺延盯防时长（秒）
pub const KILL_HOLD_RESPAWN_EXTEND_SECS: u64 = 15;
/// Kill-Hold 高频轮询间隔（毫秒）
pub const KILL_HOLD_POLL_INTERVAL_MS: u64 = 250;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeProcessInfo {
    pub pid: u32,
    pub name: String,
    pub mem_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillReport {
    pub before_count: u32,
    pub after_count: u32,
    pub telemetry_cleared_bytes: u64,
    pub message: String,
    pub kill_hold_active: bool,
    pub kill_hold_remaining_secs: u32,
}

/// Kill-Hold 防复活持续盯防锁的对外快照
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KillHoldSnapshot {
    pub active: bool,
    pub remaining_secs: u32,
    pub blocked_count: u32,
    pub tx_locked: bool,
    pub reason: String,
}

/// Kill-Hold 防复活持续盯防锁状态机（线程安全由外层 RwLock 保护）
#[derive(Debug, Default)]
pub struct KillHoldController {
    deadline: Option<Instant>,
    tx_lock_count: u32,
    blocked_count: u32,
    reason: String,
}

impl KillHoldController {
    /// 启动或续期持续盯防锁（若已有更长剩余时间则保留更长者）
    pub fn start_hold(&mut self, duration_secs: u32, reason: impl Into<String>, now: Instant) {
        let dur = Duration::from_secs(duration_secs.max(5) as u64);
        let target = now + dur;
        let was_active = self.is_active_at(now);
        if !was_active {
            self.blocked_count = 0;
        }
        self.deadline = Some(match self.deadline {
            Some(existing) if existing > target => existing,
            _ => target,
        });
        self.reason = reason.into();
    }

    /// 事务级锁定（备份清理 / 快照还原 / 切节点 / 熔断未解除期间保持全程盯防）
    pub fn acquire_tx_lock(&mut self, reason: impl Into<String>, now: Instant) {
        if !self.is_active_at(now) {
            self.blocked_count = 0;
        }
        self.tx_lock_count = self.tx_lock_count.saturating_add(1);
        self.reason = reason.into();
    }

    /// 释放一次事务级锁定，并可选衔接进入持续盯防倒计时
    pub fn release_tx_lock(&mut self, post_hold_secs: Option<u32>, now: Instant) {
        self.tx_lock_count = self.tx_lock_count.saturating_sub(1);
        if let Some(secs) = post_hold_secs {
            if secs > 0 {
                let target = now + Duration::from_secs(secs as u64);
                self.deadline = Some(match self.deadline {
                    Some(existing) if existing > target => existing,
                    _ => target,
                });
            }
        }
    }

    /// 命中复活进程冒头并强杀后调用：累计拦截次数并顺延 +15s
    pub fn record_respawn_blocked(&mut self, killed: u32, now: Instant) {
        let delta = killed.max(1);
        self.blocked_count = self.blocked_count.saturating_add(delta);
        let base = match self.deadline {
            Some(existing) if existing > now => existing,
            _ => now,
        };
        self.deadline = Some(base + Duration::from_secs(KILL_HOLD_RESPAWN_EXTEND_SECS));
    }

    /// 熔断事务锁期间命中复活进程并强杀后调用：仅累计拦截次数，不叠加额外倒计时
    pub fn record_tx_respawn_blocked(&mut self, killed: u32) {
        let delta = killed.max(1);
        self.blocked_count = self.blocked_count.saturating_add(delta);
    }

    /// 优雅释放锁（手动解除或点击「安全启动 Claude」前调用）
    pub fn release(&mut self) {
        self.deadline = None;
        self.tx_lock_count = 0;
        self.blocked_count = 0;
        self.reason.clear();
    }

    /// 判定在给定时刻锁是否处于激活态（若仅倒计时且已过期则自动清理）
    pub fn is_active_at(&self, now: Instant) -> bool {
        if self.tx_lock_count > 0 {
            return true;
        }
        matches!(self.deadline, Some(d) if d > now)
    }

    /// 获取当前快照，并在倒计时自然到期后自动归零复位
    pub fn snapshot_and_sweep(&mut self, now: Instant) -> KillHoldSnapshot {
        if self.tx_lock_count == 0 {
            if let Some(d) = self.deadline {
                if d <= now {
                    self.deadline = None;
                    self.blocked_count = 0;
                    self.reason.clear();
                }
            }
        }
        let active = self.is_active_at(now);
        let remaining_secs = match self.deadline {
            Some(d) if d > now => {
                let ms = d.duration_since(now).as_millis();
                ((ms + 999) / 1000) as u32
            }
            _ => 0,
        };
        KillHoldSnapshot {
            active,
            remaining_secs,
            blocked_count: self.blocked_count,
            tx_locked: self.tx_lock_count > 0,
            reason: self.reason.clone(),
        }
    }
}

/// 判断进程名是否属于 Claude 关联主程序
pub fn is_primary_claude_exe(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "claude.exe" | "claude-code.exe" | "claude-code" | "claude_desktop.exe"
    )
}

/// 判断进程名是否属于 Claude 可能衍生的关联辅助进程（需配合父进程校验防误杀）
pub fn is_claude_helper_exe(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "chrome-native-host.exe" | "claude-ssh.exe" | "claude-helper.exe"
    )
}

/// 枚举当前运行中的 Claude Desktop 及关联进程树
/// Windows 下直接调用 Win32 CreateToolhelp32Snapshot API（零子进程创建、耗时 <0.2ms）
pub fn list_claude_processes() -> Vec<ClaudeProcessInfo> {
    #[cfg(windows)]
    {
        list_claude_processes_win32()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn list_claude_processes_win32() -> Vec<ClaudeProcessInfo> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut raw_entries: Vec<(u32, u32, String)> = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE || snapshot.is_null() {
            return Vec::new();
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                raw_entries.push((entry.th32ProcessID, entry.th32ParentProcessID, exe_name));
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
    }

    filter_claude_process_tree(&raw_entries)
}

/// 纯函数筛选 Claude 主进程与归属于 Claude 进程树的辅助子进程（便于单测与避免误杀普通浏览器扩展）
pub fn filter_claude_process_tree(entries: &[(u32, u32, String)]) -> Vec<ClaudeProcessInfo> {
    let mut claude_pids: HashSet<u32> = HashSet::new();
    for (pid, _ppid, name) in entries {
        if is_primary_claude_exe(name) {
            claude_pids.insert(*pid);
        }
    }

    // 多轮传播，捕获挂载在 Claude 进程树下的 chrome-native-host 等辅助子进程
    loop {
        let mut added = false;
        for (pid, ppid, name) in entries {
            if !claude_pids.contains(pid)
                && claude_pids.contains(ppid)
                && (is_primary_claude_exe(name) || is_claude_helper_exe(name))
            {
                claude_pids.insert(*pid);
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    entries
        .iter()
        .filter(|(pid, _, _)| claude_pids.contains(pid))
        .map(|(pid, _, name)| ClaudeProcessInfo {
            pid: *pid,
            name: name.clone(),
            mem_kb: 0,
        })
        .collect()
}

/// 解析 Windows `tasklist /FO CSV /NH` 输出（保留用于兼容与单测验证）
pub fn parse_tasklist_csv(csv: &str) -> Vec<ClaudeProcessInfo> {
    let mut list = Vec::new();
    for line in csv.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('"') {
            continue;
        }
        let cols: Vec<&str> = trimmed.trim_matches('"').split("\",\"").collect();
        if cols.len() < 5 {
            continue;
        }
        let name = cols[0].to_string();
        if !is_primary_claude_exe(&name) {
            continue;
        }
        let Ok(pid) = cols[1].trim().parse::<u32>() else {
            continue;
        };
        let digits: String = cols[4].chars().filter(|c| c.is_ascii_digit()).collect();
        let mem_kb = digits.parse::<u64>().unwrap_or(0);
        list.push(ClaudeProcessInfo { pid, name, mem_kb });
    }
    list
}

/// 强杀 Claude 进程树（跳过 onQuitCleanup 丢弃内存待传队列），可选清扫 ~/.claude/telemetry/
pub fn kill_claude_process_tree(clean_telemetry: bool) -> KillReport {
    let procs = list_claude_processes();
    let before = procs.len() as u32;

    #[cfg(windows)]
    if before > 0 {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = Command::new("taskkill")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/F", "/T", "/IM", "Claude.exe"])
            .output();
        for p in &procs {
            if !p.name.eq_ignore_ascii_case("Claude.exe") {
                let _ = Command::new("taskkill")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["/F", "/T", "/PID", &p.pid.to_string()])
                    .output();
            }
        }
    }

    let telemetry_cleared_bytes = if clean_telemetry {
        clear_claude_telemetry_cache()
    } else {
        0
    };

    let after = list_claude_processes().len() as u32;
    let message = if before == 0 && telemetry_cleared_bytes == 0 {
        "当前无运行中的 Claude 后台进程，离线遥测缓存已为 0 B。".into()
    } else {
        format!(
            "已强杀 {} 个 Claude 进程（跳过 onQuitCleanup），清扫离线遥测缓存 {} B，当前残留 {} 个。",
            before.saturating_sub(after),
            telemetry_cleared_bytes,
            after
        )
    };

    logger::log_info(
        "process",
        format!(
            "kill_claude_process_tree(clean_telemetry={clean_telemetry}): before={before}, after={after}, cleared_bytes={telemetry_cleared_bytes}"
        ),
    );

    KillReport {
        before_count: before,
        after_count: after,
        telemetry_cleared_bytes,
        message,
        kill_hold_active: false,
        kill_hold_remaining_secs: 0,
    }
}

/// 清空 ~/.claude/telemetry/ 目录内所有离线缓存文件并返回释放字节数
pub fn clear_claude_telemetry_cache() -> u64 {
    let Some(dir) = dirs::home_dir().map(|h| h.join(".claude").join("telemetry")) else {
        return 0;
    };
    clear_directory_contents(&dir)
}

pub fn clear_directory_contents(dir: &Path) -> u64 {
    let Ok(dir_meta) = fs::symlink_metadata(dir) else {
        return 0;
    };
    // 严禁跟随符号链接 / NTFS Junction，防止递归误删外部目录
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return 0;
    }
    let mut cleared = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                cleared += clear_directory_contents(&path);
                let _ = fs::remove_dir(&path);
            } else if meta.is_file() {
                let sz = meta.len();
                if fs::remove_file(&path).is_ok() {
                    cleared += sz;
                }
            }
        }
    }
    cleared
}

/// 动态追踪 Claude.exe 可执行文件路径（兼容传统 Electron 安装与 MSIX 安装包）
pub fn resolve_claude_exe_path() -> Option<PathBuf> {
    if let Some(local) = dirs::data_local_dir() {
        let classic = local.join("AnthropicClaude").join("Claude.exe");
        if classic.exists() {
            return Some(classic);
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-Command",
                "$p = Get-AppxPackage | Where-Object { $_.Name -match 'Anthropic|Claude' } | Select-Object -First 1; if ($p) { Get-ChildItem -Path $p.InstallLocation -Filter 'Claude.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName }",
            ])
            .output()
            .ok()?;
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !line.is_empty() {
            let path = PathBuf::from(line);
            if path.exists() {
                return Some(path);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_windows_tasklist_csv_accurately() {
        let sample = "\"Claude.exe\",\"12340\",\"Console\",\"1\",\"145,280 K\"\r\n\"Claude.exe\",\"12388\",\"Console\",\"1\",\"38,120 K\"\r\n\"notepad.exe\",\"999\",\"Console\",\"1\",\"5,000 K\"\r\n";
        let procs = parse_tasklist_csv(sample);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 12340);
        assert_eq!(procs[0].mem_kb, 145280);
        assert_eq!(procs[1].pid, 12388);
    }

    #[test]
    fn win32_process_enumeration_runs_without_error() {
        let start = Instant::now();
        let _procs = list_claude_processes();
        assert!(start.elapsed().as_millis() < 500);
    }

    #[test]
    fn filters_claude_tree_without_touching_unrelated_chrome_native_host() {
        let entries = vec![
            (100, 1, "chrome.exe".to_string()),
            (101, 100, "chrome-native-host.exe".to_string()),
            (200, 1, "Claude.exe".to_string()),
            (201, 200, "chrome-native-host.exe".to_string()),
            (300, 1, "claude-code.exe".to_string()),
        ];
        let matched = filter_claude_process_tree(&entries);
        let pids: Vec<u32> = matched.iter().map(|p| p.pid).collect();
        assert!(pids.contains(&200));
        assert!(pids.contains(&201));
        assert!(pids.contains(&300));
        assert!(!pids.contains(&101));
    }

    #[test]
    fn kill_hold_lifecycle_respawn_extend_and_tx_lock() {
        let mut ctrl = KillHoldController::default();
        let t0 = Instant::now();

        ctrl.start_hold(45, "手动强杀", t0);
        let s0 = ctrl.snapshot_and_sweep(t0);
        assert!(s0.active);
        assert_eq!(s0.remaining_secs, 45);
        assert_eq!(s0.blocked_count, 0);

        // 10s 后拦截到复活，剩余 35s 顺延 +15s -> 50s
        let t1 = t0 + Duration::from_secs(10);
        ctrl.record_respawn_blocked(2, t1);
        let s1 = ctrl.snapshot_and_sweep(t1);
        assert!(s1.active);
        assert_eq!(s1.remaining_secs, 50);
        assert_eq!(s1.blocked_count, 2);

        // 事务级锁在倒计时耗尽后依然保持激活
        ctrl.acquire_tx_lock("快照还原中", t1);
        let t2 = t1 + Duration::from_secs(120);
        let s2 = ctrl.snapshot_and_sweep(t2);
        assert!(s2.active);
        assert!(s2.tx_locked);

        // 释放事务锁并衔接到 45s 盯防
        ctrl.release_tx_lock(Some(45), t2);
        let s3 = ctrl.snapshot_and_sweep(t2);
        assert!(s3.active);
        assert!(!s3.tx_locked);
        assert_eq!(s3.remaining_secs, 45);

        // 安全启动前优雅释放
        ctrl.release();
        let s4 = ctrl.snapshot_and_sweep(t2);
        assert!(!s4.active);
        assert_eq!(s4.remaining_secs, 0);
        assert_eq!(s4.blocked_count, 0);
    }

    #[test]
    fn clears_telemetry_directory_and_reports_freed_bytes() {
        let dir = tempdir().unwrap();
        let f1 = dir.path().join("event1.json");
        fs::write(&f1, b"1234567890").unwrap();
        let freed = clear_directory_contents(dir.path());
        assert_eq!(freed, 10);
        assert!(!f1.exists());
    }
}
