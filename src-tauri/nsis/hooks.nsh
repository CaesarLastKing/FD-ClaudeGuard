; FD Claude Guard NSIS Uninstall Hook
; 1. 先静默结束可能仍在后台运行的进程，避免文件占用卡住卸载或覆盖升级
; 2. 仅在真正卸载（$UpdateMode <> 1）时清理防火墙守护规则，防止残留拦截规则影响卸载后使用 Claude
; 3. 绝不调用易卡死的 PowerShell Get-NetFirewallRule，仅用极速 netsh 清理固定规则，1 秒内完成卸载

!macro NSIS_HOOK_POSTINSTALL
  ; 安装进度条完成后自动跳到「安装完成」页，不再停留在 Completed 界面多点一次 Next
  SetAutoClose true
  ; 安装或覆盖升级完成后主动通知 Windows Shell 刷新桌面/任务栏图标缓存
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToStack 'taskkill /F /IM fd-claude-guard.exe'
  Pop $0
  Pop $1
  ${If} $UpdateMode <> 1
    MessageBox MB_OK|MB_ICONINFORMATION "卸载提示：卸载 FD Claude 安全启动器将同步清空防火墙守护规则，确保卸载后网络恢复正常。"
    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="FDClaudeGuard_KillSwitch_BlockOut"'
    Pop $0
    Pop $1
    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="FDClaudeGuard_KillSwitch_WakeWindow"'
    Pop $0
    Pop $1
    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="FDClaudeGuard_KillSwitch_Probe"'
    Pop $0
    Pop $1
    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="FDGuard_Block_Claude_Out"'
    Pop $0
    Pop $1
    nsExec::ExecToStack 'schtasks /Delete /F /TN "FDClaudeGuard_FirewallHelper"'
    Pop $0
    Pop $1
  ${EndIf}
!macroend
