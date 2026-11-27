import { useCallback, useState, type MouseEvent } from "react";

export interface HoverTipState {
  text: string;
  x: number;
  y: number;
  placeBelow: boolean;
}

/**
 * 0ms 即时浮现解释气泡 Hook
 * - 自动按 rect.top < 140 判断朝下或朝上弹出，避免视口边缘裁切
 * - 滚动或移出时立即隐藏
 */
export function useHoverTooltip() {
  const [tip, setTip] = useState<HoverTipState | null>(null);

  const showTip = useCallback((e: MouseEvent<HTMLElement>, text: string) => {
    if (!text) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = Math.max(154, Math.min(window.innerWidth - 154, rect.left + rect.width / 2));
    const placeBelow = rect.top < 140;
    const y = placeBelow ? rect.bottom + 8 : rect.top - 8;
    setTip({ text, x, y, placeBelow });
  }, []);

  const hideTip = useCallback(() => {
    setTip(null);
  }, []);

  return { tip, showTip, hideTip };
}

interface HoverTooltipProps {
  tip: HoverTipState | null;
  testId?: string;
}

/**
 * 固定定位 0ms 悬停解释气泡层
 */
export function HoverTooltip({ tip, testId = "node-hover-tooltip" }: HoverTooltipProps) {
  if (!tip) return null;
  return (
    <div
      role="tooltip"
      data-testid={testId}
      className="fd-hover-tooltip"
      style={{
        left: tip.x,
        top: tip.y,
        transform: tip.placeBelow ? "translate(-50%, 0)" : "translate(-50%, -100%)",
      }}
    >
      {tip.text}
    </div>
  );
}
