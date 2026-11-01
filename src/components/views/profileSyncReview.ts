import type { ProfileSyncDiffPreview, ProfileSyncDuplicate } from '@/types/governance';

/** A duplicate must reach the admin too: merging can change access, and a conflict needs them to act. */
export function profileSyncNeedsReview(preview: ProfileSyncDiffPreview): boolean {
  return preview.removedFromOrg.length > 0 || preview.duplicates.length > 0;
}

export function describeProfileDuplicate(duplicate: ProfileSyncDuplicate): string {
  if (duplicate.outcome === 'conflict') {
    return 'Left unchanged: these rows have different groups and merging them would add access. Delete one row or give them the same groups, then pull again.';
  }
  if (duplicate.grantedGroupNames.length > 0) {
    return `Merged, and this adds access: the row in force today has no groups, so this Profile will start granting ${duplicate.grantedGroupNames.join(', ')}.`;
  }
  return 'Merged into one row. Access does not change.';
}

/** The toast after an apply. A Profile the sync could not settle must not read as a clean sync. */
export function profileSyncResultMessage(
  summary:
    | { inserted?: number; updated?: number; affected?: { duplicatesUnresolved?: string[] } }
    | null
    | undefined
): string {
  const upserted = (summary?.inserted || 0) + (summary?.updated || 0);
  const unresolved = summary?.affected?.duplicatesUnresolved || [];
  const message = `Synced Profiles from Salesforce Org (${upserted} upserted)`;
  return unresolved.length > 0
    ? `${message}. Not synced, stored twice with different groups: ${unresolved.join(', ')}`
    : message;
}
