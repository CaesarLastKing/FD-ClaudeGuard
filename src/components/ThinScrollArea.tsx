import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
  type UIEventHandler,
} from "react";

interface ThinScrollAreaProps {
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  style?: CSSProperties;
  bodyStyle?: CSSProperties;
  "data-testid"?: string;
  bodyTestId?: string;
  onScrollCapture?: UIEventHandler<HTMLDivElement>;
}

const THUMB_HEIGHT = 46;
const TRACK_INSET = 20;

/**
 * 全站统一 3×46px 悬浮细滑块滚动容器
 * - 隐藏系统原生粗长灰滚动条
 * - 通过 ResizeObserver + MutationObserver + children 同步保持滑块位置与显隐实时准确
 * - 支持鼠标拖拽滑块，同时不阻断滚轮/触控板/键盘滚动
 */
export function ThinScrollArea({
  children,
  className = "",
  bodyClassName = "",
  style,
  bodyStyle,
  "data-testid": testId,
  bodyTestId,
  onScrollCapture,
}: ThinScrollAreaProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const contentRef = useRef<HTMLDivElement | null>(null);
  const thumbRef = useRef<HTMLDivElement | null>(null);
  const hideTimerRef = useRef<number | null>(null);
  const dragStateRef = useRef<{ active: boolean; startY: number; startTop: number }>({
    active: false,
    startY: 0,
    startTop: 0,
  });

  const [isScrolling, setIsScrolling] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const syncThumb = useCallback(() => {
    const host = hostRef.current;
    const body = bodyRef.current;
    const thumb = thumbRef.current;
    if (!host || !body || !thumb) return;

    const scrollMax = body.scrollHeight - body.clientHeight;
    if (scrollMax <= 2) {
      thumb.style.opacity = "0";
      thumb.style.pointerEvents = "none";
      return;
    }

    const trackRange = Math.max(0, host.clientHeight - TRACK_INSET - THUMB_HEIGHT);
    const ratio = Math.min(1, Math.max(0, body.scrollTop / scrollMax));
    thumb.style.opacity = "1";
    thumb.style.pointerEvents = "auto";
    thumb.style.transform = `translateY(${Math.round(ratio * trackRange)}px)`;
  }, []);

  useEffect(() => {
    const rafId = window.requestAnimationFrame(syncThumb);
    return () => window.cancelAnimationFrame(rafId);
  }, [children, syncThumb]);

  useEffect(() => {
    const body = bodyRef.current;
    const content = contentRef.current;
    if (!body) return;

    const onScroll = () => {
      setIsScrolling(true);
      syncThumb();
      if (hideTimerRef.current !== null) {
        window.clearTimeout(hideTimerRef.current);
      }
      hideTimerRef.current = window.setTimeout(() => {
        setIsScrolling(false);
        hideTimerRef.current = null;
      }, 550);
    };

    const onMouseMove = (e: MouseEvent) => {
      if (!dragStateRef.current.active) return;
      const host = hostRef.current;
      if (!host) return;
      const scrollMax = body.scrollHeight - body.clientHeight;
      const trackRange = Math.max(1, host.clientHeight - TRACK_INSET - THUMB_HEIGHT);
      const deltaY = e.clientY - dragStateRef.current.startY;
      body.scrollTop = dragStateRef.current.startTop + (deltaY / trackRange) * scrollMax;
    };

    const onMouseUp = () => {
      if (!dragStateRef.current.active) return;
      dragStateRef.current.active = false;
      setIsDragging(false);
      setIsScrolling(false);
    };

    body.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    window.addEventListener("resize", syncThumb);

    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(() => {
        window.requestAnimationFrame(syncThumb);
      });
      ro.observe(body);
      if (content) ro.observe(content);
    }

    let mo: MutationObserver | null = null;
    if (typeof MutationObserver !== "undefined" && content) {
      mo = new MutationObserver(() => {
        window.requestAnimationFrame(syncThumb);
      });
      mo.observe(content, { childList: true, subtree: true, attributes: true });
    }

    syncThumb();

    return () => {
      body.removeEventListener("scroll", onScroll);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      window.removeEventListener("resize", syncThumb);
      ro?.disconnect();
      mo?.disconnect();
      if (hideTimerRef.current !== null) {
        window.clearTimeout(hideTimerRef.current);
      }
    };
  }, [syncThumb]);

  const handleThumbMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    const body = bodyRef.current;
    if (!body) return;
    e.preventDefault();
    dragStateRef.current = {
      active: true,
      startY: e.clientY,
      startTop: body.scrollTop,
    };
    setIsDragging(true);
    setIsScrolling(true);
  };

  return (
    <div
      ref={hostRef}
      data-testid={testId}
      className={`thin-scroll-host ${isScrolling ? "is-scrolling" : ""} ${
        isDragging ? "is-dragging" : ""
      } ${className}`.trim()}
      style={style}
      onScrollCapture={onScrollCapture}
    >
      <div
        ref={bodyRef}
        data-testid={bodyTestId}
        className={`thin-scroll-body ${bodyClassName}`.trim()}
        style={bodyStyle}
      >
        <div ref={contentRef} style={{ minHeight: "100%", display: "flex", flexDirection: "column" }}>
          {children}
        </div>
      </div>
      <div className="thin-scroll-track" aria-hidden="true">
        <div
          ref={thumbRef}
          className="thin-scroll-thumb"
          style={{ opacity: 0, pointerEvents: "none" }}
          onMouseDown={handleThumbMouseDown}
        />
      </div>
    </div>
  );
}
