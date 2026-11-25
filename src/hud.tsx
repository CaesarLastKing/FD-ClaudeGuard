import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HudCard } from "@/components/HudCard";
import "./styles/theme.css";

createRoot(document.getElementById("hud-root")!).render(
  <StrictMode>
    <HudCard />
  </StrictMode>
);
