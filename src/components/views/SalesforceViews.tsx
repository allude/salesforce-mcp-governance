'use client';

import React, { useState, useMemo } from 'react';
import type {
  SalesforceProfile,
  SalesforceObject,
  SalesforceObjectField,
  AccessGroup,
  ProfileGroupMapping,
  SalesforceConnectionSettings,
  ProfileSyncDiffPreview,
  OrgObjectCatalogEntry,
  ObjectSyncDiffPreview,
  RemovalResolutionAction,
} from '@/types/governance';
import { Switch, Timestamp } from '@/components/ui/primitives';
import { effectiveGrants, grantsAccess, readableGrants } from '@/rbac/groupGrants';
import type { FlyoutState } from './FlyoutDrawer';
import { describeProfileDuplicate, profileSyncNeedsReview } from './profileSyncReview';
import { profilesCsv } from './csvExport';
import {
  fieldResolutionKey,
  objectResolutionKey,
  objectSyncNeedsReview,
  objectSyncRemovals,
  otherFieldVariants,
  otherObjectVariants,
} from './objectSyncReview';

// ============================================================================
// 1. SALESFORCE PROFILES VIEW
// ============================================================================
interface SalesforceProfilesViewProps {
  profiles: SalesforceProfile[];
  groups: AccessGroup[];
  objects: SalesforceObject[];
  mappings: ProfileGroupMapping[];
  sfSettings: SalesforceConnectionSettings | null;
  selectedFlyoutId?: string;
  onOpenFlyout: (flyout: FlyoutState) => void;
  onPreviewPullProfilesFromOrg: () => Promise<ProfileSyncDiffPreview>;
  onApplyPullProfilesFromOrg: (payload: {
    upserts: Array<{ id: string; name: string }>;
    removeProfileIds: string[];
    keptMissingProfileIds: string[];
  }) => Promise<void>;
  onNavigateToOrgConnection: () => void;
}

export function SalesforceProfilesView({
  profiles,
  groups,
  objects,
  mappings,
  sfSettings,
  selectedFlyoutId,
  onOpenFlyout,
  onPreviewPullProfilesFromOrg,
  onApplyPullProfilesFromOrg,
  onNavigateToOrgConnection,
}: SalesforceProfilesViewProps) {
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'assigned' | 'unassigned' | 'missing'
  >('all');

  // Org Pull & Reconciliation state
  const [pullBusy, setPullBusy] = useState(false);
  const [pullError, setPullError] = useState('');
  const [pullPreview, setPullPreview] =
    useState<ProfileSyncDiffPreview | null>(null);
  const [resolutions, setResolutions] = useState<
    Record<string, RemovalResolutionAction>
  >({});

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const rows = useMemo(() => {
    return profiles.filter((p) => {
      const gIds = getProfileGroupIds(p.id);
      if (statusFilter === 'assigned' && gIds.length === 0) return false;
      if (statusFilter === 'unassigned' && gIds.length > 0) return false;
      if (statusFilter === 'missing' && !p.missingInOrg) return false;
      if (
        q &&
        !p.name.toLowerCase().includes(q.toLowerCase()) &&
        !p.id.toLowerCase().includes(q.toLowerCase())
      ) {
        return false;
      }
      return true;
    });
  }, [profiles, mappings, statusFilter, q]);

  const computeEffectiveSummary = (profileId: string) => {
    const gIds = getProfileGroupIds(profileId);
    const assigned = groups.filter((g) => gIds.includes(g.id));
    const actSet = new Set<string>();
    const objSet = new Set<string>();
    for (const g of assigned) {
      (g.allowedActions || []).forEach((a) => actSet.add(a));
      // As the policy engine reads them, so this never counts access /mcp does not give.
      for (const op of effectiveGrants(g.objectPermissions, objects)) {
        objSet.add(op.objectName);
      }
    }
    return {
      assignedGroups: assigned,
      actionCount: actSet.size,
      objectCount: objSet.size,
    };
  };

  const exportCsv = () => {
    const blob = new Blob([profilesCsv(profiles)], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'salesforce-profiles.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePullFromOrg = async () => {
    setPullError('');
    if (sfSettings?.connectionStatus !== 'connected') {
      onNavigateToOrgConnection();
      return;
    }
    setPullBusy(true);
    try {
      const preview = await onPreviewPullProfilesFromOrg();
      const upserts = [
        ...preview.added.map((a) => ({ id: a.id, name: a.name })),
        ...preview.updated.map((u) => ({ id: u.id, name: u.name })),
      ];
      if (!profileSyncNeedsReview(preview)) {
        await onApplyPullProfilesFromOrg({
          upserts,
          removeProfileIds: [],
          keptMissingProfileIds: [],
        });
      } else {
        const initRes: Record<string, RemovalResolutionAction> = {};
        preview.removedFromOrg.forEach((mp) => {
          initRes[mp.id] = 'KEEP_FLAGGED';
        });
        setResolutions(initRes);
        setPullPreview(preview);
      }
    } catch (err: any) {
      setPullError(err.message || 'Failed to pull profiles from Salesforce.');
    } finally {
      setPullBusy(false);
    }
  };

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Salesforce profiles</h1>
          <p>
            Map Salesforce Profile IDs to human-readable profile names used by
            the access matrix.
          </p>
        </div>
        <div className="ph-act">
          <button
            type="button"
            className="btn"
            disabled={pullBusy}
            onClick={handlePullFromOrg}
          >
            <span
              className={`dot ${
                sfSettings?.connectionStatus === 'connected' ? 'ok' : 'off'
              }`}
            />
            {pullBusy ? 'Pulling from Org…' : 'Pull from Salesforce Org'}
          </button>
          <button type="button" className="btn" onClick={exportCsv}>
            Export CSV
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onOpenFlyout({ type: 'import' })}
          >
            Import CSV
          </button>
          <button
            type="button"
            className="btn pri"
            onClick={() => onOpenFlyout({ type: 'newprofile' })}
          >
            + Add profile
          </button>
        </div>
      </div>

      {pullError && (
        <div
          className="card"
          style={{
            marginBottom: 12,
            borderColor: 'var(--err)',
            padding: '10px 14px',
            color: 'var(--err)',
          }}
        >
          {pullError}
        </div>
      )}

      {/* Org Profile Removal Reconciliation Modal */}
      {pullPreview && (
        <div className="cmdk-scrim" onClick={() => setPullPreview(null)}>
          <div
            className="cmdk-box"
            style={{ maxWidth: 680 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-h">
              <div>
                <div className="card-t">
                  Reconcile Profiles with Salesforce Org
                </div>
                <div className="card-s">
                  {pullPreview.added.length} new ·{' '}
                  {pullPreview.updated.length} existing ·{' '}
                  {pullPreview.removedFromOrg.length} local profile(s) missing
                  in Org
                  {pullPreview.duplicates.length > 0 &&
                    ` · ${pullPreview.duplicates.length} stored more than once`}
                </div>
              </div>
              <button
                type="button"
                className="btn gh sm"
                onClick={() => setPullPreview(null)}
              >
                ✕
              </button>
            </div>
            <div className="card-b">
              {pullPreview.duplicates.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div
                    style={{ fontSize: 12, color: 'var(--t2)', marginBottom: 8 }}
                  >
                    These Profiles are stored under both forms of their
                    Salesforce ID:
                  </div>
                  <div className="chk-list" style={{ maxHeight: 200 }}>
                    {pullPreview.duplicates.map((dup) => (
                      <div className="chk-row" key={dup.id}>
                        <div>
                          <div style={{ fontWeight: 500 }}>{dup.name}</div>
                          {dup.rows.map((row) => (
                            <div
                              className="mono"
                              style={{ color: 'var(--t3)' }}
                              key={row.id}
                            >
                              {row.id} · Groups:{' '}
                              {row.groupNames.join(', ') || 'None'}
                            </div>
                          ))}
                          <div style={{ fontSize: 12, marginTop: 4 }}>
                            {describeProfileDuplicate(dup)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {pullPreview.removedFromOrg.length > 0 && (
                <>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: 8,
                    }}
                  >
                    <span style={{ fontSize: 12, color: 'var(--t2)' }}>
                      Choose how to handle local profiles missing from the
                      Salesforce Org:
                    </span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button
                        type="button"
                        className="btn sm"
                        onClick={() => {
                          const next: Record<string, RemovalResolutionAction> = {};
                          pullPreview.removedFromOrg.forEach(
                            (p) => (next[p.id] = 'KEEP_FLAGGED')
                          );
                          setResolutions(next);
                        }}
                      >
                        Keep all (flag Missing in Org)
                      </button>
                      <button
                        type="button"
                        className="btn dng sm"
                        onClick={() => {
                          const next: Record<string, RemovalResolutionAction> = {};
                          pullPreview.removedFromOrg.forEach(
                            (p) => (next[p.id] = 'DELETE')
                          );
                          setResolutions(next);
                        }}
                      >
                        Remove all missing
                      </button>
                    </div>
                  </div>
                  <div className="chk-list" style={{ maxHeight: 280 }}>
                    {pullPreview.removedFromOrg.map((mp) => {
                      const choice = resolutions[mp.id] || 'KEEP_FLAGGED';
                      return (
                        <div className="chk-row" key={mp.id}>
                          <div>
                            <div style={{ fontWeight: 500 }}>{mp.name}</div>
                            <div className="mono" style={{ color: 'var(--t3)' }}>
                              {mp.id} · Mapped groups:{' '}
                              {mp.mappedGroupNames.join(', ') || 'None'}
                            </div>
                          </div>
                          <div className="seg">
                            <button
                              type="button"
                              className={choice === 'KEEP_FLAGGED' ? 'on' : ''}
                              onClick={() =>
                                setResolutions({
                                  ...resolutions,
                                  [mp.id]: 'KEEP_FLAGGED',
                                })
                              }
                            >
                              Keep &amp; Flag
                            </button>
                            <button
                              type="button"
                              className={choice === 'DELETE' ? 'on' : ''}
                              onClick={() =>
                                setResolutions({
                                  ...resolutions,
                                  [mp.id]: 'DELETE',
                                })
                              }
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'flex-end',
                  gap: 8,
                  marginTop: 12,
                }}
              >
                <button
                  type="button"
                  className="btn"
                  onClick={() => setPullPreview(null)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn pri"
                  disabled={pullBusy}
                  onClick={async () => {
                    setPullBusy(true);
                    try {
                      const upserts = [
                        ...pullPreview.added.map((a) => ({
                          id: a.id,
                          name: a.name,
                        })),
                        ...pullPreview.updated.map((u) => ({
                          id: u.id,
                          name: u.name,
                        })),
                      ];
                      const removeProfileIds = pullPreview.removedFromOrg
                        .filter((p) => resolutions[p.id] === 'DELETE')
                        .map((p) => p.id);
                      const keptMissingProfileIds = pullPreview.removedFromOrg
                        .filter((p) => resolutions[p.id] !== 'DELETE')
                        .map((p) => p.id);
                      await onApplyPullProfilesFromOrg({
                        upserts,
                        removeProfileIds,
                        keptMissingProfileIds,
                      });
                      setPullPreview(null);
                    } catch {
                      // The error toast is already showing; stay here so the admin can retry.
                    } finally {
                      setPullBusy(false);
                    }
                  }}
                >
                  Apply Org Sync
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="tbar">
          <div className="tbar-l">
            <div className="srch">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3.5-3.5" />
              </svg>
              <input
                placeholder="Search profile name or ID…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <div className="seg">
              {(
                [
                  ['all', 'All'],
                  ['assigned', 'Assigned'],
                  ['unassigned', 'Unassigned'],
                  ...(profiles.some((p) => p.missingInOrg)
                    ? [['missing', 'Missing in Org'] as const]
                    : []),
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={statusFilter === k ? 'on' : ''}
                  onClick={() => setStatusFilter(k as any)}
                >
                  {lbl}
                </button>
              ))}
            </div>
          </div>
          <div className="tbar-r">
            <span className="mono" style={{ color: 'var(--t3)' }}>
              {rows.length} of {profiles.length} profiles
            </span>
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Profile name</th>
                <th>Profile ID</th>
                <th>Assigned groups</th>
                <th>Effective access</th>
                <th>Org status</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty">
                    No profiles match your filter.
                  </td>
                </tr>
              ) : (
                rows.map((p) => {
                  const eff = computeEffectiveSummary(p.id);
                  return (
                    <tr
                      key={p.id}
                      className={`row ${
                        selectedFlyoutId === p.id ? 'sel' : ''
                      }`}
                      onClick={() =>
                        onOpenFlyout({ type: 'profile', data: p })
                      }
                    >
                      <td style={{ fontWeight: 500 }}>{p.name}</td>
                      <td className="mono" style={{ color: 'var(--t2)' }}>
                        {p.id}
                      </td>
                      <td>
                        {eff.assignedGroups.length === 0 ? (
                          <span className="tag warn">
                            <span className="dot warn" /> Unassigned
                          </span>
                        ) : (
                          <div
                            style={{
                              display: 'flex',
                              gap: 4,
                              flexWrap: 'wrap',
                            }}
                          >
                            {eff.assignedGroups.map((g) => (
                              <span key={g.id} className="tag acc">
                                {g.name}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="mono" style={{ color: 'var(--t2)' }}>
                        {eff.assignedGroups.length === 0
                          ? 'No MCP access'
                          : `${eff.actionCount} actions · ${eff.objectCount} objects`}
                      </td>
                      <td>
                        {p.missingInOrg ? (
                          <span className="tag warn">Missing in Org</span>
                        ) : (
                          <span className="tag ok">Active</span>
                        )}
                      </td>
                      <td className="mono" style={{ color: 'var(--t2)' }}>
                        <Timestamp iso={p.updatedAt} precision="date" />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// 2. SALESFORCE OBJECTS VIEW
// ============================================================================
interface SalesforceObjectsViewProps {
  objects: SalesforceObject[];
  groups: AccessGroup[];
  sfSettings: SalesforceConnectionSettings | null;
  selectedFlyoutId?: string;
  externalCatalogTrigger?: number;
  onToggleObject: (objectName: string, enabled: boolean) => Promise<void>;
  onBulkToggleAllObjects: (enabled: boolean) => Promise<void>;
  onOpenFlyout: (flyout: FlyoutState) => void;
  onFetchOrgObjectCatalog: () => Promise<OrgObjectCatalogEntry[]>;
  onPreviewPullObjectsFromOrg: (objectNames: string[]) => Promise<{
    preview: ObjectSyncDiffPreview;
    pulledMetadata: any[];
  }>;
  onApplyPullObjectsFromOrg: (payload: {
    pulledMetadata: any[];
    removeObjectNames: string[];
    removeFields: Array<{ objectName: string; fieldName: string }>;
  }) => Promise<void>;
  onNavigateToOrgConnection: () => void;
}

export function SalesforceObjectsView({
  objects,
  groups,
  sfSettings,
  selectedFlyoutId,
  externalCatalogTrigger,
  onToggleObject,
  onBulkToggleAllObjects,
  onOpenFlyout,
  onFetchOrgObjectCatalog,
  onPreviewPullObjectsFromOrg,
  onApplyPullObjectsFromOrg,
  onNavigateToOrgConnection,
}: SalesforceObjectsViewProps) {
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState<
    'all' | 'enabled' | 'disabled'
  >('all');
  const [kindFilter, setKindFilter] = useState<'all' | 'std' | 'custom'>('all');

  // Org Object Catalog & Reconciliation Modal state
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState('');
  const [catalogEntries, setCatalogEntries] = useState<
    OrgObjectCatalogEntry[]
  >([]);
  const [selectedOrgObjs, setSelectedOrgObjs] = useState<string[]>([]);
  const [catalogSearch, setCatalogSearch] = useState('');
  const [syncPreview, setSyncPreview] =
    useState<ObjectSyncDiffPreview | null>(null);
  const [pulledMetadataCache, setPulledMetadataCache] = useState<any[]>([]);
  const [objResolutions, setObjResolutions] = useState<
    Record<string, RemovalResolutionAction>
  >({});
  const [fldResolutions, setFldResolutions] = useState<
    Record<string, RemovalResolutionAction>
  >({});

  const openOrgCatalog = async () => {
    setCatalogError('');
    if (sfSettings?.connectionStatus !== 'connected') {
      onNavigateToOrgConnection();
      return;
    }
    setCatalogOpen(true);
    setCatalogLoading(true);
    setSyncPreview(null);
    try {
      const items = await onFetchOrgObjectCatalog();
      setCatalogEntries(items);
      const trackedNames = new Set(objects.map((o) => o.objectName));
      const preselected = items
        .filter((it) => trackedNames.has(it.objectName))
        .map((it) => it.objectName);
      setSelectedOrgObjs(
        preselected.length > 0
          ? preselected
          : items.slice(0, 6).map((it) => it.objectName)
      );
    } catch (err: any) {
      setCatalogError(
        err.message || 'Failed to fetch SObject catalog from Salesforce Org.'
      );
    } finally {
      setCatalogLoading(false);
    }
  };

  React.useEffect(() => {
    if (externalCatalogTrigger && externalCatalogTrigger > 0) {
      openOrgCatalog();
    }
  }, [externalCatalogTrigger]);

  const rows = useMemo(() => {
    return objects.filter(
      (o) =>
        (statusFilter === 'all' ||
          (statusFilter === 'enabled' ? o.enabled : !o.enabled)) &&
        (kindFilter === 'all' ||
          (kindFilter === 'custom' ? o.isCustom : !o.isCustom)) &&
        (!q ||
          o.objectName.toLowerCase().includes(q.toLowerCase()) ||
          o.label.toLowerCase().includes(q.toLowerCase()))
    );
  }, [objects, statusFilter, kindFilter, q]);

  const totalFields = objects.reduce((acc, o) => acc + o.fields.length, 0);
  const enabledFields = objects.reduce(
    (acc, o) =>
      acc +
      o.fields.filter((f: SalesforceObjectField) => f.enabled).length,
    0
  );

  const handlePreviewOrgSync = async () => {
    setCatalogLoading(true);
    setCatalogError('');
    try {
      const { preview, pulledMetadata } =
        await onPreviewPullObjectsFromOrg(selectedOrgObjs);
      setPulledMetadataCache(pulledMetadata);

      if (!objectSyncNeedsReview(preview)) {
        await onApplyPullObjectsFromOrg({
          pulledMetadata,
          removeObjectNames: [],
          removeFields: [],
        });
        setCatalogOpen(false);
      } else {
        // Nothing is resolved yet, and an unresolved removal reads as Keep & Flag.
        setObjResolutions({});
        setFldResolutions({});
        setSyncPreview(preview);
      }
    } catch (err: any) {
      setCatalogError(err.message || 'Failed to preview Org object sync.');
    } finally {
      setCatalogLoading(false);
    }
  };

  const allRemovedFieldsInPreview = useMemo(() => {
    if (!syncPreview) return [];
    return syncPreview.upsertedObjects.flatMap((uo) => uo.removedFieldsFromOrg);
  }, [syncPreview]);

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Salesforce objects</h1>
          <p>
            Enable or disable SObjects and individual fields exposed by the MCP
            server.
          </p>
        </div>
        <div className="ph-act">
          <button type="button" className="btn" onClick={openOrgCatalog}>
            <span
              className={`dot ${
                sfSettings?.connectionStatus === 'connected' ? 'ok' : 'off'
              }`}
            />
            Pull from Salesforce Org
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onBulkToggleAllObjects(true)}
          >
            Enable all
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => onBulkToggleAllObjects(false)}
          >
            Disable all
          </button>
          <button
            type="button"
            className="btn pri"
            onClick={() => onOpenFlyout({ type: 'sync' })}
          >
            Sync SFDX / Upload
          </button>
        </div>
      </div>

      {/* Org Object Catalog & Reconciliation Modal */}
      {catalogOpen && (
        <div className="cmdk-scrim" onClick={() => setCatalogOpen(false)}>
          <div
            className="cmdk-box"
            style={{ maxWidth: 720 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-h">
              <div>
                <div className="card-t">
                  {syncPreview
                    ? 'Reconcile Missing SObjects & Fields'
                    : 'Pull SObjects from Connected Salesforce Org'}
                </div>
                <div className="card-s">
                  {syncPreview
                    ? `${syncPreview.removedObjectsFromOrg.length} missing object(s) · ${allRemovedFieldsInPreview.length} missing field(s)`
                    : `Select SObjects from describeGlobal to describe & sync into the MCP server`}
                </div>
              </div>
              <button
                type="button"
                className="btn gh sm"
                onClick={() => setCatalogOpen(false)}
              >
                ✕
              </button>
            </div>

            <div className="card-b">
              {catalogError && (
                <div
                  style={{
                    color: 'var(--err)',
                    marginBottom: 10,
                    fontSize: 12,
                  }}
                >
                  {catalogError}
                </div>
              )}

              {!syncPreview ? (
                <>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: 8,
                      marginBottom: 8,
                    }}
                  >
                    <input
                      className="inp"
                      placeholder="Filter Org SObjects…"
                      value={catalogSearch}
                      onChange={(e) => setCatalogSearch(e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        setSelectedOrgObjs(
                          catalogEntries.map((c) => c.objectName)
                        )
                      }
                    >
                      Select all ({catalogEntries.length})
                    </button>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() => setSelectedOrgObjs([])}
                    >
                      Clear
                    </button>
                  </div>
                  <div className="chk-list" style={{ maxHeight: 300 }}>
                    {catalogLoading ? (
                      <div className="empty">
                        Querying Salesforce REST describeGlobal…
                      </div>
                    ) : (
                      catalogEntries
                        .filter(
                          (c) =>
                            !catalogSearch ||
                            c.objectName
                              .toLowerCase()
                              .includes(catalogSearch.toLowerCase()) ||
                            c.label
                              .toLowerCase()
                              .includes(catalogSearch.toLowerCase())
                        )
                        .map((c) => {
                          const on = selectedOrgObjs.includes(c.objectName);
                          const inStore = objects.some(
                            (o) => o.objectName === c.objectName
                          );
                          return (
                            <div className="chk-row" key={c.objectName}>
                              <div>
                                <span
                                  className="mono"
                                  style={{ fontWeight: 600 }}
                                >
                                  {c.objectName}
                                </span>{' '}
                                <span style={{ color: 'var(--t2)' }}>
                                  · {c.label}
                                </span>
                                {(c.isCustom || c.custom) && (
                                  <span
                                    className="tag pur"
                                    style={{ marginLeft: 6 }}
                                  >
                                    custom
                                  </span>
                                )}
                                {inStore && (
                                  <span
                                    className="tag acc"
                                    style={{ marginLeft: 6 }}
                                  >
                                    in store
                                  </span>
                                )}
                              </div>
                              <Switch
                                checked={on}
                                label={`Select ${c.objectName} to sync`}
                                onCheckedChange={() => {
                                  if (on) {
                                    setSelectedOrgObjs(
                                      selectedOrgObjs.filter(
                                        (x) => x !== c.objectName
                                      )
                                    );
                                  } else {
                                    setSelectedOrgObjs([
                                      ...selectedOrgObjs,
                                      c.objectName,
                                    ]);
                                  }
                                }}
                              />
                            </div>
                          );
                        })
                    )}
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginTop: 12,
                    }}
                  >
                    <span className="mono" style={{ color: 'var(--t3)' }}>
                      {selectedOrgObjs.length} SObjects selected
                    </span>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => setCatalogOpen(false)}
                      >
                        Cancel
                      </button>
                      <button
                        type="button"
                        className="btn pri"
                        disabled={
                          catalogLoading || selectedOrgObjs.length === 0
                        }
                        onClick={handlePreviewOrgSync}
                      >
                        {catalogLoading
                          ? 'Inspecting Schemas…'
                          : `Pull ${selectedOrgObjs.length} Objects`}
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="chk-list" style={{ maxHeight: 300 }}>
                    {syncPreview.upsertedObjects
                      .filter((uo) => uo.caseVariants.length > 0)
                      .map((uo) => (
                        <div className="chk-row" key={`variants-${uo.objectName}`}>
                          <div>
                            <span className="tag warn">Case variants</span>{' '}
                            <b className="mono">
                              {uo.caseVariants.join(', ')}
                            </b>
                            <div style={{ fontSize: 11, color: 'var(--t3)' }}>
                              One object in the org, stored as separate rows.
                              This sync updates each row and does not merge
                              them.
                            </div>
                          </div>
                        </div>
                      ))}
                    {syncPreview.removedObjectsFromOrg.map((mo) => {
                      const resolutionKey = objectResolutionKey(mo.objectName);
                      const choice =
                        objResolutions[resolutionKey] || 'KEEP_FLAGGED';
                      const variants = otherObjectVariants(
                        syncPreview,
                        mo.objectName
                      );
                      return (
                        <div className="chk-row" key={mo.objectName}>
                          <div>
                            <span className="tag warn">Object</span>{' '}
                            <b className="mono">{mo.objectName}</b> ({mo.label})
                            <div
                              style={{ fontSize: 11, color: 'var(--t3)' }}
                            >
                              {mo.fieldCount} fields · Used by groups:{' '}
                              {mo.referencedInGroups.join(', ') || 'None'}
                            </div>
                            {variants.length > 0 && (
                              <div style={{ fontSize: 11, color: 'var(--t3)' }}>
                                Your choice also applies to {variants.join(', ')}
                              </div>
                            )}
                          </div>
                          <div className="seg">
                            <button
                              type="button"
                              className={choice === 'KEEP_FLAGGED' ? 'on' : ''}
                              onClick={() =>
                                setObjResolutions({
                                  ...objResolutions,
                                  [resolutionKey]: 'KEEP_FLAGGED',
                                })
                              }
                            >
                              Keep &amp; Flag
                            </button>
                            <button
                              type="button"
                              className={choice === 'DELETE' ? 'on' : ''}
                              onClick={() =>
                                setObjResolutions({
                                  ...objResolutions,
                                  [resolutionKey]: 'DELETE',
                                })
                              }
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      );
                    })}
                    {allRemovedFieldsInPreview.map((mf) => {
                      const rowKey = `${mf.objectName}.${mf.fieldName}`;
                      const key = fieldResolutionKey(mf.objectName, mf.fieldName);
                      const choice = fldResolutions[key] || 'KEEP_FLAGGED';
                      const variants = otherFieldVariants(syncPreview, mf);
                      return (
                        <div className="chk-row" key={rowKey}>
                          <div>
                            <span className="tag">Field</span>{' '}
                            <span className="mono">
                              {mf.objectName}.{mf.fieldName}
                            </span>{' '}
                            ({mf.label})
                            {variants.length > 0 && (
                              <div style={{ fontSize: 11, color: 'var(--t3)' }}>
                                Your choice also applies to {variants.join(', ')}
                              </div>
                            )}
                          </div>
                          <div className="seg">
                            <button
                              type="button"
                              className={choice === 'KEEP_FLAGGED' ? 'on' : ''}
                              onClick={() =>
                                setFldResolutions({
                                  ...fldResolutions,
                                  [key]: 'KEEP_FLAGGED',
                                })
                              }
                            >
                              Keep &amp; Flag
                            </button>
                            <button
                              type="button"
                              className={choice === 'DELETE' ? 'on' : ''}
                              onClick={() =>
                                setFldResolutions({
                                  ...fldResolutions,
                                  [key]: 'DELETE',
                                })
                              }
                            >
                              Delete
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'flex-end',
                      gap: 8,
                      marginTop: 12,
                    }}
                  >
                    <button
                      type="button"
                      className="btn"
                      onClick={() => setSyncPreview(null)}
                    >
                      Back
                    </button>
                    <button
                      type="button"
                      className="btn pri"
                      disabled={catalogLoading}
                      onClick={async () => {
                        setCatalogLoading(true);
                        try {
                          const { removeObjectNames, removeFields } =
                            objectSyncRemovals(
                              syncPreview,
                              objResolutions,
                              fldResolutions
                            );

                          await onApplyPullObjectsFromOrg({
                            pulledMetadata: pulledMetadataCache,
                            removeObjectNames,
                            removeFields,
                          });
                          setCatalogOpen(false);
                        } catch {
                          // The error toast is already showing; stay here so the admin can retry.
                        } finally {
                          setCatalogLoading(false);
                        }
                      }}
                    >
                      Apply Sync &amp; Resolutions
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="tbar">
          <div className="tbar-l">
            <div className="srch">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.75"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3.5-3.5" />
              </svg>
              <input
                placeholder="Search object API name or label…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <div className="seg">
              {(
                [
                  ['all', 'All'],
                  ['enabled', 'Enabled'],
                  ['disabled', 'Disabled'],
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={statusFilter === k ? 'on' : ''}
                  onClick={() => setStatusFilter(k)}
                >
                  {lbl}
                </button>
              ))}
            </div>
            <div className="seg">
              {(
                [
                  ['all', 'All'],
                  ['std', 'Standard'],
                  ['custom', 'Custom (__c)'],
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={kindFilter === k ? 'on' : ''}
                  onClick={() => setKindFilter(k)}
                >
                  {lbl}
                </button>
              ))}
            </div>
          </div>
          <div className="tbar-r">
            <span className="mono" style={{ color: 'var(--t3)' }}>
              {objects.filter((o) => o.enabled).length} enabled ·{' '}
              {enabledFields}/{totalFields} fields
            </span>
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 64 }}>Enabled</th>
                <th>Object API name</th>
                <th>Label</th>
                <th>Category</th>
                <th>Fields enabled</th>
                <th>Used in groups</th>
                <th>Source</th>
                <th>Last synced</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty">
                    No objects match your filter.
                  </td>
                </tr>
              ) : (
                rows.map((o) => {
                  const fOn = o.fields.filter(
                    (f: SalesforceObjectField) => f.enabled
                  ).length;
                  const usedBy = groups.filter((g) =>
                    readableGrants(g.objectPermissions).some(
                      (op) => op.objectName === o.objectName && grantsAccess(op)
                    )
                  );

                  return (
                    <tr
                      key={o.objectName}
                      className={`row ${
                        selectedFlyoutId === o.objectName ? 'sel' : ''
                      }`}
                      onClick={() =>
                        onOpenFlyout({ type: 'object', data: o })
                      }
                    >
                      <td onClick={(e) => e.stopPropagation()}>
                        <Switch
                          checked={o.enabled}
                          label={`Enable ${o.objectName} for MCP`}
                          onCheckedChange={(next) => onToggleObject(o.objectName, next)}
                        />
                      </td>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        <div
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                          }}
                        >
                          <span>{o.objectName}</span>
                          {o.missingInOrg && (
                            <span className="tag warn">Missing in Org</span>
                          )}
                        </div>
                      </td>
                      <td>{o.label}</td>
                      <td>
                        <span className={`tag ${o.isCustom ? 'pur' : ''}`}>
                          {o.isCustom ? 'Custom' : 'Standard'}
                        </span>
                      </td>
                      <td>
                        <span className="mono">
                          {fOn} / {o.fields.length}
                        </span>
                      </td>
                      <td>
                        {usedBy.length === 0 ? (
                          <span style={{ color: 'var(--t3)', fontSize: 12 }}>
                            —
                          </span>
                        ) : (
                          <span className="tag">
                            {usedBy.length} group
                            {usedBy.length === 1 ? '' : 's'}
                          </span>
                        )}
                      </td>
                      <td>
                        <span className="tag mono">{o.sourcePath}</span>
                      </td>
                      <td className="mono" style={{ color: 'var(--t2)' }}>
                        <Timestamp iso={o.updatedAt} precision="date" />
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
