use std::env;

fn main() {
    #[cfg(windows)]
    {
        // T-034：为正式桌面主程序嵌入管理员 UAC 清单（requireAdministrator），确保 Defender 防火墙熔断规则 100% 可写（fw=true）
        // 仅在 Release 发行构建中注入，避免日常 cargo test 单元测试二进制触发 UAC 弹窗
        if env::var("PROFILE").as_deref() == Ok("release") {
            let windows = tauri_build::WindowsAttributes::new().app_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>
"#,
            );
            tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
                .expect("failed to run tauri-build with admin manifest");
        } else {
            tauri_build::build();
        }
    }
    #[cfg(not(windows))]
    {
        tauri_build::build();
    }

    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=icons/32x32.png");
    println!("cargo:rerun-if-changed=icons/128x128.png");
    println!("cargo:rerun-if-changed=icons/128x128@2x.png");
    println!("cargo:rerun-if-changed=../clash-scripts/claude-verge-override.js");
}
