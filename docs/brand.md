# mcpwatch brand guide

## Name
- Always **mcpwatch**: one word, all lowercase, even at the start of a sentence. Never "MCPWatch", "MCP Watch" or "McpWatch".
- Product feature names: **Rug-pull radar** (the daily change feed), **index**, **grade**, **lockfile** (`mcpwatch.lock`).

## Voice
- Calm, precise, developer-native. State facts and mechanisms; no hype, no fear-selling.
- Use "rug pull" only for the generic threat and the feature name. Never label a named server's change a rug pull: say "tool changed", "changed tool description".
- Describe grades as automated, read-only signals from public data, not audits or accusations. Do not call the index "static": it does a live read-only probe (MCP handshake + tool listing). The CLI scan is static.
- Headline: "Know when the tools your AI agents trust change."

## Logo
A rounded-square tile with a radar ring that has a gap, a sweep line pointing at the gap, and a centre dot: "watching, and pointing at what changed".
- Files: `web/assets/logo.svg` (mark + wordmark), `web/assets/favicon.svg` (mark). On the site the mark is inlined in the header and the favicon is a data: URI (CSP allows no external assets).
- Minimum size 16px. Clear space: half the tile width on every side. Teal tile with white strokes on light backgrounds; in dark mode the tile becomes `#2dd4bf` with `#042f2b` strokes. Do not recolour, rotate, outline or add effects.
- Wordmark: system sans, weight 650, letter-spacing -0.01em, 10px gap after the mark.

## Colour tokens (CSS custom properties in `mcpwatch/index.py`)
| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#ffffff` | `#0b0f12` | page |
| `--sf` | `#f6f8f9` | `#12191d` | cards, table headers |
| `--fg` | `#0e1417` | `#e6edf0` | text |
| `--mut` | `#55616b` | `#9aa7b0` | secondary text |
| `--line` | `#e1e6ea` | `#243038` | borders |
| `--acc` | `#0f766e` | `#2dd4bf` | links, primary button, focus ring |
| `--on` | `#ffffff` | `#042f2b` | text on `--acc` |
| `--soft` | `#e6f4f2` | `#0f2a28` | eyebrow pill background |

Contrast (WCAG 2.1): fg/bg 18.6 (light) / 16.3 (dark); mut/bg 6.35 / 7.81; mut/sf 5.96 / 7.21; acc/bg 5.47 / 10.34; acc/sf 5.14 / 9.54; on/acc 5.47 / 7.80; acc/soft 4.84 / 8.16. All pass AA for normal text.

### Grade colours (same in both themes, white bold letter, letter always shown)
| Grade | Hex | White text contrast |
|---|---|---|
| A | `#1a7f37` | 5.08 |
| B | `#4d7c0f` | 4.99 |
| C | `#8a5a00` | 5.93 |
| D | `#bc4c00` | 5.03 |
| F | `#c4222e` | 5.81 |
| ? (badge, unknown) | `#6e7781` | 4.55 |

A is best, F is worst. Colour is never the only signal: the letter is always rendered (plus visually hidden "Grade" for screen readers). Severities (Critical/High/Medium/Low) are neutral text labels with no alarm colour.

### Badge
`/badge/<slug>.svg`, 128x20: label side `#1f2a30` with the teal radar mark (`#2dd4bf`) and "mcpwatch" in white (14.7:1), value side is the grade colour. `mcpwatch/scan.py badge()` and `api/badge.js svg()` must stay byte-identical.

## Type
- Sans: `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`. Mono: `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`. No web fonts (CSP and speed).
- Scale (rem at 16px base): 0.75 (table headers, uppercase), 0.8125 (code, labels), 0.875 (small/meta), 1 (body, line-height 1.6), 1.125 (lede), 1.375 (h2), clamp(1.875–2.75) (h1). Headings use letter-spacing -0.02em, weights 650–700.
- Spacing on a 4px grid; radius 10px for cards, 8px for buttons/code, 6px for chips.

## Accessibility rules
Visible 2px `--acc` focus ring, skip link, 44px minimum button height, no horizontal scroll at 360px (`.wrap` breaks long registry names), `prefers-reduced-motion` disables transitions, all untrusted text escaped (Python `esc()`, JS `textContent`).
