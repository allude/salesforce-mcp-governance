/** Whether a value has the shape of a Salesforce ID. The checksum of an 18-character ID is not verified. */
export function isSalesforceId(id: string): boolean {
  return /^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$/.test((id || '').trim());
}

/**
 * What identifies a Salesforce ID. IDs are 15-char case-sensitive or 18-char with a checksum suffix,
 * so the key is the first 15 characters, keeping their case. Anything else is compared whole.
 */
export function salesforceIdKey(id: string): string {
  const clean = (id || '').trim();
  return isSalesforceId(clean) ? clean.slice(0, 15) : clean;
}

/** Whether two values are forms of one Salesforce ID. An empty value matches nothing. */
export function salesforceIdsMatch(a: string, b: string): boolean {
  const left = salesforceIdKey(a);
  return left !== '' && left === salesforceIdKey(b);
}
