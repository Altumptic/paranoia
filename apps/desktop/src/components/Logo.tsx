import { useId } from "react";

import { WHALE_EYE, WHALE_PATH, WHALE_VIEWBOX } from "../brand/whale";

/** The Paranoia whale, drawn in the current theme's accent (clay). */
export function Whale({ size = 28, className }: { size?: number; className?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg className={className} width={size} height={(size * 60.2) / 120} viewBox={WHALE_VIEWBOX} role="img" aria-label="Paranoia">
      <defs>
        <linearGradient id={`g${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--accent-2)" />
          <stop offset="1" stopColor="var(--accent)" />
        </linearGradient>
        <mask id={`m${id}`}>
          <rect width="120" height="61" fill="#fff" />
          <circle cx={WHALE_EYE.cx} cy={WHALE_EYE.cy} r={WHALE_EYE.r} fill="#000" />
        </mask>
      </defs>
      <path d={WHALE_PATH} fill={`url(#g${id})`} mask={`url(#m${id})`} />
    </svg>
  );
}
