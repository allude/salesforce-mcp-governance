/** How many of `fields` differ between a form's draft and what the server holds (for the form bars). */
export function changedFieldCount<T extends object>(draft: T, saved: T, fields: readonly (keyof T)[]): number {
  return fields.filter((field) => !sameValue(draft[field], saved[field])).length;
}

function sameValue(a: unknown, b: unknown): boolean {
  // An empty field and an absent one are the same to the admin.
  const norm = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v.trim() : v);
  return norm(a) === norm(b);
}
