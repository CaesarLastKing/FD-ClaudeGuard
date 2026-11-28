; FD Claude Guard NSIS Install & Uninstall Hook
; 1. 安装前自动结束运行中实例，并检测静默卸载历史 currentUser（%LOCALAPPDATA%\FD Claude Guard）残留，避免双份共存
; 2. 安装完成后自动跳过等待页并刷新图标缓存
; 3. 仅在真正卸载（$UpdateMode <> 1）时清理防火墙守护规则与计划任务，确保卸载后网络恢复正常

!macro NSIS_HOOK_PREINSTALL
  ; 先静默结束可能仍在运行的旧实例（含旧版 currentUser 与 perMachine 实例），防止文件占用或单实例锁冲突
  nsExec::ExecToStack 'taskkill /F /T /IM fd-claude-guard.exe'
  Pop $0
  Pop $1
  Sleep 400

  ; 显式切至 current 用户上下文，精准定位历史 currentUser 模式（%LOCALAPPDATA%\FD Claude Guard）残留
  SetShellVarContext current
  ${If} ${FileExists} "$LOCALAPPDATA\FD Claude Guard\uninstall.exe"
    nsExec::ExecToStack '"$LOCALAPPDATA\FD Claude Guard\uninstall.exe" /S _?=$LOCALAPPDATA\FD Claude Guard'
    Pop $0
    Pop $1
    Sleep 800
  ${EndIf}
  ${If} ${FileExists} "$LOCALAPPDATA\FD Claude Guard\fd-claude-guard.exe"
    RMDir /r "$LOCALAPPDATA\FD Claude Guard"
  ${EndIf}
  ${If} ${FileExists} "$LOCALAPPDATA\FD Claude Guard\uninstall.exe"
    RMDir /r "$LOCALAPPDATA\FD Claude Guard"
  ${EndIf}
  ; 清理可能残留的旧 currentUser 快捷方式与 HKCU 卸载注册表项（静默忽略不存在项）
  Delete "$SMPROGRAMS\FD Claude Guard.lnk"
  RMDir /r "$SMPROGRAMS\FD Claude Guard"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\FD Claude Guard"
  DeleteRegKey HKCU "Software\FD Claude Guard"
  ; 严格恢复 perMachine 所需的 all 上下文，避免影响后续新版安装目录与公共快捷方式写入
  SetShellVarContext all
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; 全新安装时默认注册 Windows 管理员高权限登录开机自启任务（卸载钩子已包含完整清理；覆盖升级交由应用按用户配置幂等对齐）
  ${If} $UpdateMode <> 1
    nsExec::ExecToStack 'schtasks /Create /F /SC ONLOGON /RL HIGHEST /TN "FDClaudeGuard_AutoStart" /TR "\"$INSTDIR\fd-claude-guard.exe\" --autostart"'
    Pop $0
    Pop $1
  ${EndIf}
  ; 安装进度条完成后自动跳到「安装完成」页，不再停留在 Completed 界面多点一次 Next
  SetAutoClose true
  ; 安装或覆盖升级完成后主动通知 Windows Shell 刷新桌面/任务栏图标缓存
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, i 0, i 0)'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToStack 'taskkill /F /T /IM fd-claude-guard.exe'
  Pop $0
  Pop $1
  Sleep 500
  ${If} $UpdateMode <> 1
    MessageBox MB_OK|MB_ICONINFORMATION "卸载提示：卸载 FD Claude 安全启动器将同步清空防火墙守护规则与开机自启计划任务，确保卸载后网络恢复正常。"
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
    nsExec::ExecToStack 'schtasks /Delete /F /TN "FDClaudeGuard_AutoStart"'
    Pop $0
    Pop $1
  ${EndIf}
!macroend
