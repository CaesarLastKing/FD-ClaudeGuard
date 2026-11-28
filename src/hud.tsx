import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HudCard } from "@/components/HudCard";
import "./styles/theme.css";

// 挂载前优先同步主窗持久化主题，消除冷启动等待 IPC 期间的首帧闪白/闪黑
try {
  const params = new URLSearchParams(window.location.search);
  const queryTheme = params.get("theme");
  const cachedTheme = window.localStorage?.getItem("fd-guard-theme");
  const initialTheme =
    queryTheme === "light" || queryTheme === "dark"
      ? queryTheme
      : cachedTheme === "light" || cachedTheme === "dark"
      ? cachedTheme
      : null;
  if (initialTheme) {
    document.documentElement.setAttribute("data-theme", initialTheme);
  }
} catch {
  // 忽略预览/受限存储环境异常
}

createRoot(document.getElementById("hud-root")!).render(
  <StrictMode>
    <HudCard />
  </StrictMode>
);
