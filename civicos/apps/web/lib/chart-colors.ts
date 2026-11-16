// Chart colours as hex, because Recharts and MapLibre write them into SVG/WebGL, where CSS variables do not apply.
// Lives outside any "use client" file so server components can import the values too.
// Keep in sync with the chart tokens in app/globals.css. Validated on the panel surface for dark mode.
export const SERIES = { one: "#3987e5", two: "#d95926", three: "#199e70" };
export const STATUS = { good: "#0ca30c", warning: "#fab219", serious: "#ec835a", critical: "#d03b3b" };

/** Categorical colours in fixed order. Only the first three are colour-blind safe when every pair can touch (a map), so groups are capped at three. */
export const GROUP_COLORS = [SERIES.one, SERIES.two, SERIES.three];

/** Diverging pair for above/below average: blue and red poles, grey midpoint. */
export const DIVERGING = { pos: "#3987e5", neg: "#e66767", mid: "#383835" };
