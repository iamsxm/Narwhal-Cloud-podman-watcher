# Design System Master File - Apple iOS 18

> **LOGIC:** When building or updating frontend pages for Narwhal Monitor, strictly follow the iOS 18 specifications below.

---

**Project:** Narwhal Monitor
**Design System:** Apple iOS 18 Human Interface Guidelines (Liquid Glass & Squircles)
**Category:** RPA / Container Security & Operations Center
**Design Dials:** Vibrancy 9/10 (Frosted Glass / Neon System Accents) | Motion 8/10 (Fluid Springs) | Density 7/10 (iOS Inset Grouped Hierarchy)

---

## Global Rules

### Color Palette (iOS 18 System Colors)

| Role | Dark Hex | Light Hex | CSS Variable |
|------|----------|-----------|--------------|
| Primary / Tint Blue | `#0A84FF` | `#007AFF` | `--color-primary` |
| On Primary | `#FFFFFF` | `#FFFFFF` | `--color-on-primary` |
| Success / System Green | `#30D158` | `#34C759` | `--color-success` |
| Warning / System Orange | `#FF9F0A` | `#FF9500` | `--color-warning` |
| Destructive / System Red | `#FF453A` | `#FF3B30` | `--color-destructive` |
| Purple / Accent | `#BF5AF2` | `#AF52DE` | `--color-purple` |
| Cyan / Network | `#64D2FF` | `#32ADE6` | `--color-cyan` |
| Background | `#000000` (OLED) | `#F2F2F7` | `--color-background` |
| Surface Card | `rgba(36,36,38,0.72)` | `rgba(255,255,255,0.92)` | `--color-surface-card` |
| Foreground Label | `#FFFFFF` | `#000000` | `--color-foreground` |
| Muted Secondary Label | `rgba(235,235,245,0.68)` | `rgba(60,60,67,0.68)` | `--color-foreground-muted` |
| Border / Separator | `rgba(255,255,255,0.12)` | `rgba(60,60,67,0.12)` | `--color-border` |

**Color Notes:** Deep OLED pure black canvas, frosted glass surfaces with refractive specular highlight, and vibrant iOS 18 neon accents.

### Typography (San Francisco / Apple System)

- **Heading Font:** `-apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Rounded", "PingFang SC", "Hiragino Sans GB", "Helvetica Neue", sans-serif`
- **Body Font:** `-apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro", "PingFang SC", "Hiragino Sans GB", "Helvetica Neue", sans-serif`
- **Monospace Font:** `"SF Mono", ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono", "Fira Code", monospace`
- **Mood:** Clean, precise, high-contrast, premium, native Apple feel.

### Spacing Variables (iOS 8-pt Grid)

| Token | Value | Usage |
|-------|-------|-------|
| `--space-xs` | `4px` | Tight icon spacing, subtext gap |
| `--space-sm` | `6px` | Capsule pill padding, inline gaps |
| `--space-md` | `10px` | Standard button and input padding |
| `--space-lg` | `14px` | Inset card padding, section gap |
| `--space-xl` | `18px` | Card internal padding |
| `--space-2xl` | `26px` | Page shell section margins |
| `--space-3xl` | `36px` | Modal and hero padding |

### Squircles & Corner Radii

| Level | Value | Usage |
|-------|-------|-------|
| `--radius-xs` | `6px` | Mini tags, indicator dots |
| `--radius-sm` | `10px` | Inset blocks, list rows |
| `--radius-md` | `14px` | Buttons, inputs, metric cells |
| `--radius-lg` | `20px` | Container cards, widgets |
| `--radius-xl` | `26px` | Group cards, section cards |
| `--radius-2xl` | `34px` | Modals, navigation bar |
| `--radius-full` | `9999px` | Capsule pills, segmented controls |

### Shadows & Materials

- **Frosted Acrylic:** `backdrop-filter: blur(28px) saturate(190%)`
- **Inner Glass Bezel:** `box-shadow: inset 0 1px 0.5px rgba(255, 255, 255, 0.18)`
- **Ambient Shadow:** `0 8px 24px -4px rgba(0, 0, 0, 0.32), 0 2px 6px rgba(0, 0, 0, 0.18)`

---

## Component Specs

### iOS 18 Buttons

```css
/* Primary Capsule Button */
.btn-primary {
  background: linear-gradient(180deg, #0A84FF 0%, #0070E0 100%);
  color: #FFFFFF;
  padding: 8px 16px;
  border-radius: var(--radius-md);
  font-weight: 600;
  border: 1px solid rgba(255, 255, 255, 0.2);
  box-shadow: 0 2px 10px rgba(10, 132, 255, 0.35);
  transition: all 200ms cubic-bezier(0.16, 1, 0.3, 1);
  cursor: pointer;
}

.btn-primary:active {
  transform: scale(0.96);
  opacity: 0.88;
}
```

### iOS 18 Widget Cards

```css
.card, .kpi-card, .container-card {
  background: var(--color-surface-card);
  backdrop-filter: blur(28px) saturate(190%);
  -webkit-backdrop-filter: blur(28px) saturate(190%);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: inset 0 1px 0.5px rgba(255, 255, 255, 0.18), var(--shadow-sm);
  transition: all 260ms cubic-bezier(0.16, 1, 0.3, 1);
}

.card:hover {
  transform: translateY(-3px);
  box-shadow: inset 0 1px 0.5px rgba(255, 255, 255, 0.18), var(--shadow-hover);
  border-color: var(--color-border-reveal);
}
```

### iOS 18 Segmented Controls

```css
.status-tabs {
  display: inline-flex;
  gap: 4px;
  padding: 4px;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid var(--color-border-subtle);
  border-radius: var(--radius-full);
}

.status-chip.active {
  background: var(--color-primary);
  color: #FFFFFF;
  box-shadow: 0 2px 8px rgba(10, 132, 255, 0.4);
}
```

---

## Motion Guidelines

- **Spring Feel:** `cubic-bezier(0.34, 1.56, 0.64, 1)` for active transforms and toasts.
- **Fluid Transition:** `cubic-bezier(0.16, 1, 0.3, 1)` for cards and interactive hover.
- **Accessibility:** Strictly honor `prefers-reduced-motion: reduce`.
