/** One command palette entry. */
export interface PaletteItem {
  id: string;
  section: string;
  label: string;
  meta: string;
  action: () => void;
}

export const PALETTE_MAX_ITEMS = 24;

/**
 * What the palette lists for a query: the whole list is filtered first and only then capped, so a
 * match far down (the 40th SObject, a Profile after many groups) is still found. With no query, the
 * navigation and quick actions come first, then the first entities of each kind.
 */
export function filterPaletteItems(items: readonly PaletteItem[], query: string, max = PALETTE_MAX_ITEMS): PaletteItem[] {
  const q = query.trim().toLowerCase();
  if (!q) {
    const perSection = new Map<string, number>();
    return items
      .filter((it) => {
        const n = perSection.get(it.section) ?? 0;
        perSection.set(it.section, n + 1);
        return it.section === 'Navigation' || it.section === 'Quick Actions' || n < 5;
      })
      .slice(0, max);
  }
  return items
    .filter((it) => [it.label, it.meta, it.section].some((text) => text.toLowerCase().includes(q)))
    .slice(0, max);
}
