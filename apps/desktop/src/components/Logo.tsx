import { useId } from "react";

import { WHALE_EYE, WHALE_PATH, WHALE_VIEWBOX } from "../brand/whale";

/** The Paranoia whale. `glow` adds the soft halo used on hero surfaces. */
export function Whale({ size = 28, glow = false, className }: { size?: number; glow?: boolean; className?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg
      className={className}
      width={size}
      height={(size * 60.2) / 120}
      viewBox={WHALE_VIEWBOX}
      role="img"
      aria-label="Paranoia"
      style={glow ? { filter: "drop-shadow(0 0 18px rgba(46,230,166,.45))", overflow: "visible" } : undefined}
    >
      <defs>
        <linearGradient id={`g${id}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#6CFFD0" />
          <stop offset="1" stopColor="#12B886" />
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

export function Wordmark({ size = 15 }: { size?: number }) {
  return (
    <span className="wordmark" style={{ fontSize: size }}>
      Paranoia
    </span>
  );
}
