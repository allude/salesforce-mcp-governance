'use client';

import React, { useState, useEffect } from 'react';
import {
  Plus,
  Trash2,
  Save,
  Check,
  Shield,
  Layers,
  Database,
  Wrench,
  ArrowLeft,
} from 'lucide-react';
import {
  AccessGroup,
  GroupObjectPermission,
  SalesforceObject,
  SalesforceProfile,
  ProfileGroupMapping,
  AVAILABLE_MCP_ACTIONS,
  NavViewId,
} from '@/types/governance';
import { Card, Badge } from '@/components/ui/primitives';

// ============================================================================
// # ACCESS MATRIX -> ## GROUPS
// ============================================================================
export function AccessGroupsView({
  groups,
  objects,
  apiFetch,
  onRefresh,
  onShowToast,
  onNavigate,
}: {
  groups: AccessGroup[];
  objects: SalesforceObject[];
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
  onNavigate: (view: NavViewId) => void;
}) {
  const enabledObjects = objects.filter((o) => o.enabled);

  const [selectedGroupId, setSelectedGroupId] = useState<string | 'NEW'>(
    groups[0]?.id || 'NEW'
  );
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [allowedActions, setAllowedActions] = useState<string[]>([
    'list_enabled_objects',
    'describe_object',
    'soql_query',
  ]);
  const [objPerms, setObjPerms] = useState<
    Record<string, GroupObjectPermission>
  >({});
  const [saving, setSaving] = useState(false);

  // Sync editor state when switching groups
  useEffect(() => {
    if (selectedGroupId === 'NEW') {
      setGroupName('');
      setGroupDesc('');
      setAllowedActions([
        'list_enabled_objects',
        'describe_object',
        'soql_query',
      ]);
      setObjPerms({});
      return;
    }

    const found = groups.find((g) => g.id === selectedGroupId);
    if (found) {
      setGroupName(found.name);
      setGroupDesc(found.description);
      setAllowedActions(found.allowedActions);
      const map: Record<string, GroupObjectPermission> = {};
      for (const op of found.objectPermissions) {
        map[op.objectName] = {
          ...op,
          allowedFields: [...op.allowedFields],
        };
      }
      setObjPerms(map);
    }
  }, [selectedGroupId, groups]);

  const toggleAction = (actionId: string) => {
    setAllowedActions((prev) =>
      prev.includes(actionId)
        ? prev.filter((a) => a !== actionId)
        : [...prev, actionId]
    );
  };

  const getOrInitObjPerm = (obj: SalesforceObject): GroupObjectPermission => {
    return (
      objPerms[obj.objectName] || {
        objectName: obj.objectName,
        canRead: false,
        canCreate: false,
        canUpdate: false,
        canDelete: false,
        allowedFields: [],
      }
    );
  };

  const updateObjCrud = (
    obj: SalesforceObject,
    field: 'canRead' | 'canCreate' | 'canUpdate' | 'canDelete',
    value: boolean
  ) => {
    const current = getOrInitObjPerm(obj);
    const enabledFieldNames = obj.fields
      .filter((f) => f.enabled)
      .map((f) => f.fieldName);

    // If enabling Read/Create/Update for the first time and no fields are checked yet, default to all enabled fields
    const nextFields =
      value && current.allowedFields.length === 0
        ? enabledFieldNames
        : current.allowedFields;

    setObjPerms((prev) => ({
      ...prev,
      [obj.objectName]: {
        ...current,
        [field]: value,
        allowedFields: nextFields,
      },
    }));
  };

  const toggleObjField = (obj: SalesforceObject, fieldName: string) => {
    const current = getOrInitObjPerm(obj);
    const exists = current.allowedFields.includes(fieldName);
    const nextFields = exists
      ? current.allowedFields.filter((f) => f !== fieldName)
      : [...current.allowedFields, fieldName];

    setObjPerms((prev) => ({
      ...prev,
      [obj.objectName]: {
        ...current,
        canRead: nextFields.length > 0 ? true : current.canRead,
        allowedFields: nextFields,
      },
    }));
  };

  const selectAllFieldsForObj = (obj: SalesforceObject, selectAll: boolean) => {
    const current = getOrInitObjPerm(obj);
    const enabledFieldNames = obj.fields
      .filter((f) => f.enabled)
      .map((f) => f.fieldName);

    setObjPerms((prev) => ({
      ...prev,
      [obj.objectName]: {
        ...current,
        canRead: selectAll ? true : current.canRead,
        allowedFields: selectAll ? enabledFieldNames : [],
      },
    }));
  };

  const handleSaveGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupName.trim()) return;
    setSaving(true);
    try {
      const objectPermissionsList = Object.values(objPerms).filter(
        (op) =>
          op.canRead ||
          op.canCreate ||
          op.canUpdate ||
          op.canDelete ||
          op.allowedFields.length > 0
      );

      const res = await apiFetch<{ group: AccessGroup }>('/api/admin/groups', {
        method: 'POST',
        body: JSON.stringify({
          id: selectedGroupId === 'NEW' ? undefined : selectedGroupId,
          name: groupName.trim(),
          description: groupDesc.trim(),
          allowedActions,
          objectPermissions: objectPermissionsList,
        }),
      });
      await onRefresh();
      setSelectedGroupId(res.group.id);
      onShowToast(`Saved Group "${res.group.name}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteGroup = async (id: string, name: string) => {
    try {
      await apiFetch(`/api/admin/groups/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      await onRefresh();
      setSelectedGroupId('NEW');
      onShowToast(`Deleted Group "${name}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Access Groups (MCP Actions + Objects/Fields)
          </h2>
          <p className="text-xs text-slate-500">
            Create reusable permission groups that define allowed MCP actions and scoped Salesforce Objects &amp; Fields (sourced from enabled objects in `# Salesforce &gt; ## Objects`).
          </p>
        </div>

        <button
          type="button"
          onClick={() => setSelectedGroupId('NEW')}
          className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-indigo-700"
        >
          <Plus className="h-3.5 w-3.5" />
          New Access Group
        </button>
      </div>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left List of Groups */}
        <Card className="p-3 lg:col-span-4">
          <div className="mb-2 px-2 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
            Configured Groups ({groups.length})
          </div>

          <div className="space-y-1.5">
            {groups.map((g) => {
              const isSelected = selectedGroupId === g.id;
              return (
                <div
                  key={g.id}
                  onClick={() => setSelectedGroupId(g.id)}
                  className={`flex cursor-pointer items-center justify-between rounded-xl border p-3 text-xs transition ${
                    isSelected
                      ? 'border-indigo-200 bg-indigo-50/70 text-indigo-900'
                      : 'border-slate-100 bg-white text-slate-700 hover:bg-slate-50'
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="font-bold text-slate-900">{g.name}</div>
                    {g.description && (
                      <p className="truncate text-[11px] text-slate-500">
                        {g.description}
                      </p>
                    )}
                    <div className="mt-1.5 flex items-center gap-2 text-[10px] text-slate-500">
                      <Badge variant="indigo">
                        {g.allowedActions.length} Actions
                      </Badge>
                      <Badge variant="emerald">
                        {g.objectPermissions.length} Objects
                      </Badge>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteGroup(g.id, g.name);
                    }}
                    className="ml-2 rounded-lg p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                    title="Delete Group"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              );
            })}

            {groups.length === 0 && (
              <div className="rounded-xl border border-dashed border-slate-200 p-6 text-center text-xs text-slate-400">
                No groups created yet. Use the editor on the right to create your first Access Group.
              </div>
            )}
          </div>
        </Card>

        {/* Right Group Configuration Editor */}
        <Card className="p-5 lg:col-span-8">
          <form onSubmit={handleSaveGroup} className="space-y-5">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  {selectedGroupId === 'NEW'
                    ? 'Create New Access Group'
                    : `Edit Group: ${groupName}`}
                </h3>
                <p className="text-[11px] text-slate-500">
                  Profiles mapped to this group in the Profile Group Matrix inherit these MCP actions and object/field permissions.
                </p>
              </div>
              <button
                type="submit"
                disabled={saving}
                className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-indigo-700 disabled:opacity-50"
              >
                <Save className="h-3.5 w-3.5" />
                {saving ? 'Saving...' : 'Save Group'}
              </button>
            </div>

            {/* Group Name & Description */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Group Name
                </label>
                <input
                  type="text"
                  required
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  placeholder="e.g. Sales Read & Update, Support Case Triage"
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Description
                </label>
                <input
                  type="text"
                  value={groupDesc}
                  onChange={(e) => setGroupDesc(e.target.value)}
                  placeholder="Optional description of what this group grants"
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
                />
              </div>
            </div>

            {/* 1. Allowed MCP Actions */}
            <div>
              <div className="mb-2 flex items-center gap-1.5 text-xs font-bold text-slate-800">
                <Wrench className="h-3.5 w-3.5 text-indigo-600" />
                <span>1. Allowed MCP Actions</span>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {AVAILABLE_MCP_ACTIONS.map((act) => {
                  const checked = allowedActions.includes(act.id);
                  return (
                    <label
                      key={act.id}
                      className={`flex cursor-pointer items-start gap-2.5 rounded-xl border p-2.5 text-xs transition ${
                        checked
                          ? 'border-indigo-200 bg-indigo-50/50'
                          : 'border-slate-200/80 bg-white hover:bg-slate-50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleAction(act.id)}
                        className="mt-0.5 h-3.5 w-3.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono font-bold text-slate-900">
                            {act.id}
                          </span>
                          <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[10px] font-semibold text-slate-600">
                            {act.category}
                          </span>
                        </div>
                        <p className="mt-0.5 text-[11px] text-slate-500">
                          {act.description}
                        </p>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            {/* 2. Object & Field Permissions (from Enabled Salesforce Objects) */}
            <div>
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800">
                  <Database className="h-3.5 w-3.5 text-indigo-600" />
                  <span>
                    2. Salesforce Objects & Field Scoping (Enabled Objects:{' '}
                    {enabledObjects.length})
                  </span>
                </div>
                {enabledObjects.length === 0 && (
                  <button
                    type="button"
                    onClick={() => onNavigate('sf-objects')}
                    className="text-xs font-semibold text-indigo-600 hover:underline"
                  >
                    Go to Salesforce &gt; Objects to import/enable objects →
                  </button>
                )}
              </div>

              {enabledObjects.length === 0 ? (
                <div className="rounded-xl border border-dashed border-slate-200 p-6 text-center text-xs text-slate-400">
                  No enabled Salesforce Objects found. Import or enable objects under{' '}
                  <button
                    type="button"
                    onClick={() => onNavigate('sf-objects')}
                    className="font-semibold text-indigo-600 underline"
                  >
                    Salesforce &gt; Objects
                  </button>{' '}
                  first.
                </div>
              ) : (
                <div className="space-y-3">
                  {enabledObjects.map((obj) => {
                    const perm = getOrInitObjPerm(obj);
                    const enabledFields = obj.fields.filter((f) => f.enabled);
                    return (
                      <div
                        key={obj.objectName}
                        className="rounded-xl border border-slate-200/90 bg-slate-50/40 p-3.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200/70 pb-2.5">
                          <div>
                            <span className="font-mono text-xs font-bold text-slate-900">
                              {obj.objectName}
                            </span>
                            <span className="ml-2 text-xs text-slate-500">
                              ({obj.label})
                            </span>
                          </div>

                          {/* CRUD Toggles */}
                          <div className="flex items-center gap-3 text-xs">
                            {(
                              [
                                ['canRead', 'Read'],
                                ['canCreate', 'Create'],
                                ['canUpdate', 'Update'],
                                ['canDelete', 'Delete'],
                              ] as const
                            ).map(([key, label]) => (
                              <label
                                key={key}
                                className="inline-flex cursor-pointer items-center gap-1.5 font-semibold text-slate-700"
                              >
                                <input
                                  type="checkbox"
                                  checked={perm[key]}
                                  onChange={(e) =>
                                    updateObjCrud(obj, key, e.target.checked)
                                  }
                                  className="h-3.5 w-3.5 rounded border-slate-300 text-indigo-600"
                                />
                                <span>{label}</span>
                              </label>
                            ))}
                          </div>
                        </div>

                        {/* Allowed Fields Checkboxes */}
                        <div className="mt-2.5">
                          <div className="mb-1.5 flex items-center justify-between text-[11px] text-slate-500">
                            <span>
                              Allowed Fields ({perm.allowedFields.length} /{' '}
                              {enabledFields.length})
                            </span>
                            <div className="space-x-2">
                              <button
                                type="button"
                                onClick={() => selectAllFieldsForObj(obj, true)}
                                className="font-semibold text-indigo-600 hover:underline"
                              >
                                Select All
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  selectAllFieldsForObj(obj, false)
                                }
                                className="font-semibold text-slate-500 hover:underline"
                              >
                                Clear
                              </button>
                            </div>
                          </div>

                          <div className="flex flex-wrap gap-1.5">
                            {enabledFields.map((f) => {
                              const isFieldChecked =
                                perm.allowedFields.includes(f.fieldName);
                              return (
                                <button
                                  key={f.fieldName}
                                  type="button"
                                  onClick={() =>
                                    toggleObjField(obj, f.fieldName)
                                  }
                                  className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-[11px] transition ${
                                    isFieldChecked
                                      ? 'border-indigo-300 bg-indigo-50 font-semibold text-indigo-700'
                                      : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-100'
                                  }`}
                                >
                                  {isFieldChecked && (
                                    <Check className="h-3 w-3 text-indigo-600" />
                                  )}
                                  <span>{f.fieldName}</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
}

// ============================================================================
// # ACCESS MATRIX -> ## PROFILE GROUP MATRIX
// ============================================================================
export function ProfileGroupMatrixView({
  profiles,
  groups,
  mappings,
  apiFetch,
  onRefresh,
  onShowToast,
  onNavigate,
}: {
  profiles: SalesforceProfile[];
  groups: AccessGroup[];
  mappings: ProfileGroupMapping[];
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
  onNavigate: (view: NavViewId) => void;
}) {
  // Profiles with a save in flight; their row is locked so a second click cannot send a
  // replacement list computed from stale props (which could silently undo a revocation).
  const [savingProfileIds, setSavingProfileIds] = useState<Set<string>>(new Set());

  const getGroupIdsForProfile = (profileId: string): string[] => {
    return mappings.find((m) => m.profileId === profileId)?.groupIds || [];
  };

  const handleToggleProfileGroup = async (
    profileId: string,
    groupId: string
  ) => {
    if (savingProfileIds.has(profileId)) return;
    const current = getGroupIdsForProfile(profileId);
    const exists = current.includes(groupId);
    const nextGroupIds = exists
      ? current.filter((id) => id !== groupId)
      : [...current, groupId];

    setSavingProfileIds((prev) => new Set(prev).add(profileId));
    try {
      await apiFetch(
        `/api/admin/profile-groups/${encodeURIComponent(profileId)}`,
        {
          method: 'PUT',
          body: JSON.stringify({ groupIds: nextGroupIds }),
        }
      );
      onShowToast('Updated Profile-to-Group assignment');
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      try {
        // Always reload so the row shows what the server actually stored
        await onRefresh();
      } catch (err: any) {
        onShowToast(err?.message || 'Could not reload the matrix', true);
      } finally {
        setSavingProfileIds((prev) => {
          const next = new Set(prev);
          next.delete(profileId);
          return next;
        });
      }
    }
  };

  // Compute effective actions & objects for a profile across its assigned groups
  const computeEffectiveSummary = (profileId: string) => {
    const gIds = new Set(getGroupIdsForProfile(profileId));
    const assigned = groups.filter((g) => gIds.has(g.id));
    const actions = new Set<string>();
    const objects = new Set<string>();

    for (const g of assigned) {
      for (const a of g.allowedActions) actions.add(a);
      for (const o of g.objectPermissions) {
        if (o.canRead || o.canCreate || o.canUpdate || o.canDelete) {
          objects.add(o.objectName);
        }
      }
    }
    return {
      actions: Array.from(actions),
      objects: Array.from(objects),
    };
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Profile Group Matrix
          </h2>
          <p className="text-xs text-slate-500">
            Map Salesforce Profiles to one or more Access Groups. A Profile&apos;s effective permissions are the union of all Groups checked in its row.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigate('sf-profiles')}
            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
          >
            Manage Profiles ({profiles.length})
          </button>
          <button
            type="button"
            onClick={() => onNavigate('matrix-groups')}
            className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
          >
            Manage Groups ({groups.length})
          </button>
        </div>
      </div>

      <Card className="overflow-hidden">
        {profiles.length === 0 || groups.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-500">
            {profiles.length === 0 && (
              <p className="mb-2">
                No Salesforce Profiles imported yet. Go to{' '}
                <button
                  onClick={() => onNavigate('sf-profiles')}
                  className="font-bold text-indigo-600 underline"
                >
                  Salesforce &gt; Profiles
                </button>{' '}
                to import a CSV or add profiles.
              </p>
            )}
            {groups.length === 0 && (
              <p>
                No Access Groups created yet. Go to{' '}
                <button
                  onClick={() => onNavigate('matrix-groups')}
                  className="font-bold text-indigo-600 underline"
                >
                  Access Matrix &gt; Groups
                </button>{' '}
                to create a group.
              </p>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200/80 bg-slate-50/70 text-[11px] font-bold tracking-wider text-slate-500 uppercase">
                  <th className="py-3 pr-3 pl-4">Salesforce Profile</th>
                  {groups.map((g) => (
                    <th key={g.id} className="px-3 py-3 text-center">
                      <div className="font-bold text-slate-800 normal-case">
                        {g.name}
                      </div>
                      <div className="font-mono text-[10px] font-normal text-slate-400 normal-case">
                        {g.allowedActions.length} acts •{' '}
                        {g.objectPermissions.length} objs
                      </div>
                    </th>
                  ))}
                  <th className="py-3 pr-4 pl-3">
                    Effective Access (Union of Groups)
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {profiles.map((p) => {
                  const assignedIds = getGroupIdsForProfile(p.id);
                  const effective = computeEffectiveSummary(p.id);
                  return (
                    <tr key={p.id} className="hover:bg-slate-50/80">
                      <td className="py-3 pr-3 pl-4">
                        <div className="font-semibold text-slate-900">
                          {p.name}
                        </div>
                        <div className="font-mono text-[11px] text-indigo-600">
                          {p.id}
                        </div>
                      </td>

                      {groups.map((g) => {
                        const checked = assignedIds.includes(g.id);
                        return (
                          <td key={g.id} className="px-3 py-3 text-center">
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={savingProfileIds.has(p.id)}
                              onChange={() =>
                                handleToggleProfileGroup(p.id, g.id)
                              }
                              className="h-4 w-4 cursor-pointer rounded border-slate-300 text-indigo-600 focus:ring-indigo-500 disabled:cursor-wait disabled:opacity-50"
                            />
                          </td>
                        );
                      })}

                      <td className="py-3 pr-4 pl-3">
                        {effective.actions.length === 0 &&
                        effective.objects.length === 0 ? (
                          <span className="text-[11px] text-slate-400">
                            No effective access (Blocked)
                          </span>
                        ) : (
                          <div className="space-y-1">
                            <div className="flex flex-wrap gap-1">
                              {effective.objects.map((oName) => (
                                <Badge key={oName} variant="emerald">
                                  Obj: {oName}
                                </Badge>
                              ))}
                            </div>
                            <div className="font-mono text-[10px] text-slate-500">
                              Actions: {effective.actions.join(', ')}
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
