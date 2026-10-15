import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, type ReactNode } from "react";

/** Fixed-row-height virtualized list. */
export function VirtualList<T>({
  items,
  rowHeight = 26,
  render,
  activeIndex,
  className,
}: {
  items: T[];
  rowHeight?: number;
  render(item: T, index: number): ReactNode;
  /** Scrolled into view when it changes. */
  activeIndex?: number;
  className?: string;
}) {
  const parent = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({
    count: items.length,
    getScrollElement: () => parent.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });

  useEffect(() => {
    if (activeIndex != null && activeIndex >= 0) v.scrollToIndex(activeIndex, { align: "auto" });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIndex]);

  return (
    <div ref={parent} className={`vlist ${className ?? ""}`}>
      <div style={{ height: v.getTotalSize(), position: "relative" }}>
        {v.getVirtualItems().map((row) => (
          <div
            key={row.key}
            className="vrow"
            style={{ position: "absolute", top: 0, left: 0, right: 0, height: rowHeight, transform: `translateY(${row.start}px)` }}
          >
            {render(items[row.index], row.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
