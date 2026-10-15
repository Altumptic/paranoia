import { useId } from "react";

import { WHALE_EYE, WHALE_PATH, WHALE_VIEWBOX } from "../brand/whale";

/** The Paranoia whale: flat, in the theme's clay accent, with the eye cut out. */
export function Whale({ size = 28, className }: { size?: number; className?: string }) {
  const id = useId().replace(/:/g, "");
  return (
    <svg className={className} width={size} height={(size * 60.2) / 120} viewBox={WHALE_VIEWBOX} role="img" aria-label="Paranoia">
      <mask id={`m${id}`}>
        <rect width="120" height="61" fill="#fff" />
        <circle cx={WHALE_EYE.cx} cy={WHALE_EYE.cy} r={WHALE_EYE.r} fill="#000" />
      </mask>
      <path d={WHALE_PATH} fill="var(--accent)" mask={`url(#m${id})`} />
    </svg>
  );
}

/** The app icon: clay tile, ivory whale and a quiet swell line (matches assets/brand/app-icon.svg). */
export function AppIcon({ size = 64, className }: { size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="48 48 928 928" role="img" aria-label="Paranoia">
      <rect x="48" y="48" width="928" height="928" rx="212" fill="#D97757" />
      <g transform="translate(188 300) scale(5.4)">
        <path d={WHALE_PATH} fill="#FAF9F5" />
        <circle cx={WHALE_EYE.cx} cy={WHALE_EYE.cy} r={WHALE_EYE.r} fill="#D97757" />
      </g>
      <path d="M330 716 C 410 694, 470 694, 540 712 S 668 732, 740 708" fill="none" stroke="#FAF9F5" strokeOpacity=".45" strokeWidth="14" strokeLinecap="round" />
    </svg>
  );
}
