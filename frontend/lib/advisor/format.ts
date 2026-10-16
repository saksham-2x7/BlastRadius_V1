export const fmtEpssText = (epss: number) => (epss < 0.01 ? "<1%" : `${Math.round(epss * 100)}%`);
