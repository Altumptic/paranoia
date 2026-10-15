# Brand

The Paranoia mark is a whale traced from the original drawing (`assets/brand/whale.jpg`) into a single vector path (`apps/desktop/src/brand/whale.ts`).

| Token | Hex | Use |
| --- | --- | --- |
| Clay | `#D97757` | Primary accent, app icon tile, the whale |
| Clay (deep) | `#C6613F` | Hover / pressed states on light backgrounds |
| Ivory | `#FAF9F5` | Light background, whale on the app icon |
| Graphite | `#1F1E1D` | Dark background, text on light |

Typography: **Source Serif 4** for headings and the wordmark, **Inter** for UI, **JetBrains Mono** for code.

Assets:

- `assets/brand/app-icon.svg` — app icon (clay tile, ivory whale, swell line); PNG/ICO renders live in `apps/desktop/build/`
- `assets/brand/paranoia-mark.svg` / `paranoia-mark-ivory.svg` — the whale alone
- `assets/brand/lockup-light.png` / `lockup-dark.png` — whale + wordmark

Regenerate the SVGs with `node scripts/brand.mjs`. The design keeps to flat colour — no gradients, glows or outlines.
