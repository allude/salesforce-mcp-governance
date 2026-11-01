'use client';

import React, { useState, useMemo } from 'react';
import type {
  AccessGroup,
  SalesforceObjectConfig,
  SalesforceProfile,
  ProfileGroupMapping,
} from '@/types/governance';
import { formatDateShort } from '@/components/ui/primitives';
import type { FlyoutState } from './FlyoutDrawer';
import { newAccessGroupDraft } from './accessGroupDraft';

// ============================================================================
// 1. ACCESS GROUPS VIEW
// ============================================================================
interface AccessGroupsViewProps {
  groups: AccessGroup[];
  objects: SalesforceObjectConfig[];
  profiles: SalesforceProfile[];
  mappings: ProfileGroupMapping[];
  selectedFlyoutId?: string;
  onOpenFlyout: (flyout: FlyoutState) => void;
  onSeedEnterpriseMatrix?: () => void;
}

export function AccessGroupsView({
  groups,
  profiles,
  mappings,
  selectedFlyoutId,
  onOpenFlyout,
  onSeedEnterpriseMatrix,
}: AccessGroupsViewProps) {
  const [q, setQ] = useState('');

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const rows = useMemo(() => {
    return groups.filter(
      (g) =>
        !q ||
        g.name.toLowerCase().includes(q.toLowerCase()) ||
        g.description.toLowerCase().includes(q.toLowerCase())
    );
  }, [groups, q]);

  const handleNewGroup = () => {
    onOpenFlyout({
      type: 'group',
      data: newAccessGroupDraft(),
    });
  };

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Access groups</h1>
          <p>
            Define which MCP actions and Salesforce objects a group can use.
            Assign profiles to groups in Profile &harr; Group.
          </p>
        </div>
        <div className="ph-act">
          {groups.length <= 1 && onSeedEnterpriseMatrix && (
            <button
              type="button"
              className="btn"
              onClick={onSeedEnterpriseMatrix}
            >
              Load enterprise groups
            </button>
          )}
          <button type="button" className="btn pri" onClick={handleNewGroup}>
            + New group
          </button>
        </div>
      </div>

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
                placeholder="Search groups…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
          </div>
          <div className="tbar-r">
            <span style={{ fontSize: 11.5, color: 'var(--t3)' }}>
              Click a group to edit actions, objects &amp; fields
            </span>
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Group</th>
                <th>MCP actions</th>
                <th>Object permissions (R·C·U·D)</th>
                <th>Assigned profiles</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    No access groups match your filter. Click &ldquo;+ New
                    group&rdquo; to create one.
                  </td>
                </tr>
              ) : (
                rows.map((g) => {
                  const assignedCount = profiles.filter((p) =>
                    getProfileGroupIds(p.id).includes(g.id)
                  ).length;
                  const activeObjPerms = (g.objectPermissions || []).filter(
                    (op) =>
                      op.canRead || op.canCreate || op.canUpdate || op.canDelete
                  );

                  return (
                    <tr
                      key={g.id}
                      className={`row ${
                        selectedFlyoutId === g.id ? 'sel' : ''
                      }`}
                      onClick={() =>
                        onOpenFlyout({ type: 'group', data: g })
                      }
                    >
                      <td>
                        <div style={{ fontWeight: 600 }}>{g.name}</div>
                        <div
                          style={{
                            fontSize: 11.5,
                            color: 'var(--t3)',
                            marginTop: 2,
                          }}
                        >
                          {g.description}
                        </div>
                      </td>
                      <td>
                        <div
                          style={{
                            display: 'flex',
                            gap: 4,
                            flexWrap: 'wrap',
                            maxWidth: 290,
                          }}
                        >
                          {(g.allowedActions || []).slice(0, 4).map((a) => (
                            <span
                              key={a}
                              className={`tag mono ${
                                a === 'delete_record' ? 'err' : ''
                              }`}
                            >
                              {a}
                            </span>
                          ))}
                          {(g.allowedActions || []).length > 4 && (
                            <span className="tag mono">
                              +{g.allowedActions.length - 4}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div
                          style={{
                            display: 'flex',
                            gap: 6,
                            flexWrap: 'wrap',
                          }}
                        >
                          {activeObjPerms.length === 0 ? (
                            <span style={{ color: 'var(--t3)', fontSize: 12 }}>
                              No objects configured
                            </span>
                          ) : (
                            activeObjPerms.slice(0, 6).map((op) => {
                              const letters = [
                                op.canRead ? 'R' : null,
                                op.canCreate ? 'C' : null,
                                op.canUpdate ? 'U' : null,
                                op.canDelete ? 'D' : null,
                              ]
                                .filter(Boolean)
                                .join('');
                              return (
                                <span
                                  key={op.objectName}
                                  className="tag mono"
                                  style={{ gap: 6 }}
                                >
                                  <b>{op.objectName}</b>
                                  <span
                                    style={{
                                      color: op.canDelete
                                        ? 'var(--err)'
                                        : 'var(--acc)',
                                    }}
                                  >
                                    {letters}
                                  </span>
                                </span>
                              );
                            })
                          )}
                          {activeObjPerms.length > 6 && (
                            <span className="tag mono">
                              +{activeObjPerms.length - 6} more
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <span
                          className={`tag ${assignedCount ? 'acc' : ''}`}
                        >
                          {assignedCount} profile
                          {assignedCount === 1 ? '' : 's'}
                        </span>
                      </td>
                      <td className="mono" style={{ color: 'var(--t2)' }}>
                        {formatDateShort(g.updatedAt)}
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
// 2. PROFILE <-> GROUP MATRIX VIEW
// ============================================================================
interface ProfileGroupMatrixViewProps {
  profiles: SalesforceProfile[];
  groups: AccessGroup[];
  objects: SalesforceObjectConfig[];
  mappings: ProfileGroupMapping[];
  onToggleProfileGroup: (profileId: string, groupId: string) => Promise<void>;
  onOpenFlyout: (flyout: FlyoutState) => void;
  onSeedEnterpriseMatrix?: () => void;
}

export function ProfileGroupMatrixView({
  profiles,
  groups,
  objects,
  mappings,
  onToggleProfileGroup,
  onOpenFlyout,
  onSeedEnterpriseMatrix,
}: ProfileGroupMatrixViewProps) {
  const [q, setQ] = useState('');
  const [onlyFilter, setOnlyFilter] = useState<
    'all' | 'assigned' | 'unassigned'
  >('all');

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const unassignedCount = useMemo(
    () =>
      profiles.filter((p) => getProfileGroupIds(p.id).length === 0).length,
    [profiles, mappings]
  );

  const totalAssignments = useMemo(
    () =>
      profiles.reduce(
        (acc, p) => acc + getProfileGroupIds(p.id).length,
        0
      ),
    [profiles, mappings]
  );

  const rows = useMemo(() => {
    return profiles.filter((p) => {
      const gIds = getProfileGroupIds(p.id);
      if (onlyFilter === 'assigned' && gIds.length === 0) return false;
      if (onlyFilter === 'unassigned' && gIds.length > 0) return false;
      if (
        q &&
        !p.name.toLowerCase().includes(q.toLowerCase()) &&
        !p.id.toLowerCase().includes(q.toLowerCase())
      ) {
        return false;
      }
      return true;
    });
  }, [profiles, mappings, onlyFilter, q]);

  const computeEffectiveCounts = (profileId: string) => {
    const gIds = getProfileGroupIds(profileId);
    const assigned = groups.filter((g) => gIds.includes(g.id));
    const actSet = new Set<string>();
    const objSet = new Set<string>();
    for (const g of assigned) {
      (g.allowedActions || []).forEach((a) => actSet.add(a));
      for (const op of g.objectPermissions || []) {
        const objMeta = objects.find((o) => o.objectName === op.objectName);
        if (objMeta && !objMeta.enabled) continue;
        if (op.canRead || op.canCreate || op.canUpdate || op.canDelete) {
          objSet.add(op.objectName);
        }
      }
    }
    return {
      groupCount: gIds.length,
      actionCount: actSet.size,
      objectCount: objSet.size,
    };
  };

  return (
    <div>
      <div className="ph">
        <div className="ph-l">
          <h1>Profile &harr; Group matrix</h1>
          <p>
            Toggle cells to assign Salesforce profiles to access groups. A
            profile receives the union of permissions from all its assigned
            groups.
          </p>
        </div>
        <div className="ph-act">
          {groups.length <= 1 && onSeedEnterpriseMatrix && (
            <button
              type="button"
              className="btn"
              onClick={onSeedEnterpriseMatrix}
            >
              Load enterprise matrix
            </button>
          )}
          <button
            type="button"
            className="btn"
            onClick={() => onOpenFlyout({ type: 'simulator' })}
          >
            Simulate MCP call
          </button>
          <button
            type="button"
            className="btn pri"
            onClick={() =>
              onOpenFlyout({
                type: 'group',
                data: newAccessGroupDraft(),
              })
            }
          >
            + New group
          </button>
        </div>
      </div>

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
                placeholder="Filter profiles…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </div>
            <div className="seg">
              {(
                [
                  ['all', `All (${profiles.length})`],
                  ['assigned', 'Assigned'],
                  ['unassigned', `Unassigned (${unassignedCount})`],
                ] as const
              ).map(([k, lbl]) => (
                <button
                  key={k}
                  type="button"
                  className={onlyFilter === k ? 'on' : ''}
                  onClick={() => setOnlyFilter(k)}
                >
                  {lbl}
                </button>
              ))}
            </div>
          </div>
          <div className="tbar-r">
            <span className="mono" style={{ color: 'var(--t3)' }}>
              {totalAssignments} active assignments
            </span>
          </div>
        </div>

        <div className="tbl-wrap">
          <table className="tbl mtx">
            <thead>
              <tr>
                <th>Salesforce profile</th>
                {groups.map((g) => (
                  <th
                    className="rot"
                    key={g.id}
                    style={{ cursor: 'pointer' }}
                    title="Click to inspect or edit this group"
                    onClick={() => onOpenFlyout({ type: 'group', data: g })}
                  >
                    <div
                      style={{
                        color: 'var(--tx)',
                        textTransform: 'none',
                        letterSpacing: 0,
                        fontSize: 12,
                      }}
                    >
                      {g.name}
                    </div>
                    <div
                      className="mono"
                      style={{
                        color: 'var(--t3)',
                        fontWeight: 400,
                        fontSize: 10.5,
                        textTransform: 'none',
                      }}
                    >
                      {(g.allowedActions || []).length} actions ·{' '}
                      {(g.objectPermissions || []).length} objects
                    </div>
                  </th>
                ))}
                <th>Effective access</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={groups.length + 2} className="empty">
                    No profiles match your filter.
                  </td>
                </tr>
              ) : (
                rows.map((p) => {
                  const gIds = getProfileGroupIds(p.id);
                  const eff = computeEffectiveCounts(p.id);
                  return (
                    <tr key={p.id}>
                      <td
                        style={{ cursor: 'pointer' }}
                        onClick={() =>
                          onOpenFlyout({ type: 'profile', data: p })
                        }
                      >
                        <div
                          style={{
                            fontWeight: 500,
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                          }}
                        >
                          <span>{p.name}</span>
                          {p.missingInOrg && (
                            <span className="tag warn">Missing in Org</span>
                          )}
                        </div>
                        <div
                          className="mono"
                          style={{ color: 'var(--t3)', fontSize: 11 }}
                        >
                          {p.id}
                        </div>
                      </td>

                      {groups.map((g) => {
                        const on = gIds.includes(g.id);
                        return (
                          <td className="mc" key={g.id}>
                            <button
                              type="button"
                              className={`mcell ${on ? 'on' : ''}`}
                              title={`${p.name} ↔ ${g.name}`}
                              onClick={() => onToggleProfileGroup(p.id, g.id)}
                            >
                              <svg
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                              >
                                <path d="M5 12l5 5L20 7" />
                              </svg>
                            </button>
                          </td>
                        );
                      })}

                      <td
                        style={{ cursor: 'pointer' }}
                        onClick={() =>
                          onOpenFlyout({ type: 'profile', data: p })
                        }
                      >
                        {eff.groupCount === 0 ? (
                          <span className="tag warn">
                            <span className="dot warn" /> No access
                          </span>
                        ) : (
                          <span className="tag ok">
                            <span className="dot ok" /> {eff.actionCount}{' '}
                            actions · {eff.objectCount} objects
                          </span>
                        )}
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
