'use client';

import React, { useState, useRef } from 'react';
import {
  Upload,
  Plus,
  Trash2,
  ArrowRight,
  FolderOpen,
  HardDrive,
  Search,
  ChevronRight,
  Check,
  X,
  FileSpreadsheet,
  Database,
  SlidersHorizontal,
} from 'lucide-react';
import {
  SalesforceProfile,
  SalesforceObject,
  ProfileGroupMapping,
  AccessGroup,
  NavViewId,
} from '@/types/governance';
import { Card, Badge, Switch } from '@/components/ui/primitives';

// ============================================================================
// # SALESFORCE -> ## PROFILES
// ============================================================================
export function SalesforceProfilesView({
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
  const [search, setSearch] = useState('');
  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const [showCsvModal, setShowCsvModal] = useState(false);
  const [csvText, setCsvText] = useState('');
  const [importing, setImporting] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const filtered = profiles.filter(
    (p) =>
      !search.trim() ||
      p.id.toLowerCase().includes(search.toLowerCase()) ||
      p.name.toLowerCase().includes(search.toLowerCase())
  );

  const getGroupNamesForProfile = (profileId: string) => {
    const m = mappings.find((item) => item.profileId === profileId);
    if (!m || m.groupIds.length === 0) return [];
    return m.groupIds.map(
      (gid) => groups.find((g) => g.id === gid)?.name || gid
    );
  };

  const handleAddOrUpdateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newId.trim() || !newName.trim()) return;
    try {
      await apiFetch('/api/admin/profiles', {
        method: 'POST',
        body: JSON.stringify({ id: newId.trim(), name: newName.trim() }),
      });
      setNewId('');
      setNewName('');
      await onRefresh();
      onShowToast('Saved Salesforce Profile');
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleDeleteProfile = async (id: string, name: string) => {
    try {
      await apiFetch(`/api/admin/profiles/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      await onRefresh();
      onShowToast(`Deleted profile "${name}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleCsvFileUpload = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setCsvText(text);
    setShowCsvModal(true);
    e.target.value = '';
  };

  const handleImportCsvSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!csvText.trim()) return;
    setImporting(true);
    try {
      const res = await apiFetch<{
        summary: { inserted: number; updated: number; total: number };
      }>('/api/admin/profiles/import-csv', {
        method: 'POST',
        body: JSON.stringify({ csvText }),
      });
      await onRefresh();
      setShowCsvModal(false);
      setCsvText('');
      onShowToast(
        `CSV Imported: ${res.summary.inserted} added, ${res.summary.updated} updated (${res.summary.total} total)`
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Action Header */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-base font-bold text-slate-900">
            Salesforce Profiles
          </h2>
          <p className="text-xs text-slate-500">
            Manage Salesforce Profile IDs and Names (`00e...`). Import via CSV (`id, name`) to bulk-insert or update existing profiles.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,text/csv,text/plain"
            onChange={handleCsvFileUpload}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-2xs transition hover:bg-slate-50"
          >
            <Upload className="h-3.5 w-3.5 text-indigo-600" />
            Upload CSV File
          </button>

          <button
            type="button"
            onClick={() => setShowCsvModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-2xs transition hover:bg-slate-50"
          >
            <FileSpreadsheet className="h-3.5 w-3.5 text-indigo-600" />
            Paste CSV
          </button>

          <button
            type="button"
            onClick={() => onNavigate('matrix-profile-groups')}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-indigo-700"
          >
            <span>Go to Profile Group Matrix</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Inline Add / Update Single Profile Bar */}
      <Card className="p-3.5">
        <form
          onSubmit={handleAddOrUpdateProfile}
          className="flex flex-col gap-2.5 sm:flex-row sm:items-center"
        >
          <div className="flex-1 sm:max-w-xs">
            <input
              type="text"
              required
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              placeholder="Salesforce Profile ID (e.g. 00e8b000001SalesRp)"
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>
          <div className="flex-1">
            <input
              type="text"
              required
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Profile Name (e.g. Sales Representative)"
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-slate-800"
          >
            <Plus className="h-3.5 w-3.5" />
            Add / Update Profile
          </button>
        </form>
      </Card>

      {/* Dense Profiles Table */}
      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-slate-200/80 bg-slate-50/60 px-4 py-2.5">
          <span className="text-xs font-bold text-slate-700">
            Registered Profiles ({filtered.length})
          </span>
          <div className="relative">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by ID or Name..."
              className="w-56 rounded-lg border border-slate-200 bg-white py-1 pr-2.5 pl-8 text-xs text-slate-800 focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 bg-slate-50/40 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                <th className="py-2.5 pr-3 pl-4">Profile ID</th>
                <th className="px-3 py-2.5">Profile Name</th>
                <th className="px-3 py-2.5">Assigned Access Groups</th>
                <th className="px-3 py-2.5">Last Updated</th>
                <th className="py-2.5 pr-4 pl-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="py-10 text-center text-xs text-slate-400"
                  >
                    No profiles configured yet. Add a profile above or click{' '}
                    <span className="font-semibold text-slate-600">
                      Upload CSV File
                    </span>{' '}
                    to import `id, name`.
                  </td>
                </tr>
              ) : (
                filtered.map((p) => {
                  const assignedGroups = getGroupNamesForProfile(p.id);
                  return (
                    <tr key={p.id} className="hover:bg-slate-50/80">
                      <td className="py-2.5 pr-3 pl-4 font-mono text-xs font-semibold text-indigo-600">
                        {p.id}
                      </td>
                      <td className="px-3 py-2.5 font-semibold text-slate-900">
                        {p.name}
                      </td>
                      <td className="px-3 py-2.5">
                        {assignedGroups.length === 0 ? (
                          <span className="text-[11px] text-slate-400">
                            No groups mapped
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {assignedGroups.map((gName) => (
                              <Badge key={gName} variant="indigo">
                                {gName}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-[11px] text-slate-400">
                        {new Date(p.updatedAt).toLocaleString()}
                      </td>
                      <td className="py-2.5 pr-4 pl-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              setNewId(p.id);
                              setNewName(p.name);
                            }}
                            className="rounded-md border border-slate-200 px-2 py-1 text-[11px] font-semibold text-slate-600 hover:bg-slate-100"
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => onNavigate('matrix-profile-groups')}
                            className="rounded-md border border-indigo-200 bg-indigo-50 px-2 py-1 text-[11px] font-semibold text-indigo-600 hover:bg-indigo-100"
                          >
                            Matrix →
                          </button>
                          <button
                            type="button"
                            onClick={() => handleDeleteProfile(p.id, p.name)}
                            className="rounded-md p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                            title="Delete Profile"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* CSV Import Modal */}
      {showCsvModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 backdrop-blur-[1px]"
          onClick={() => setShowCsvModal(false)}
        >
          <div
            className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900">
                  Import Salesforce Profiles from CSV
                </h3>
                <p className="text-[11px] text-slate-500">
                  Format: 2 columns (`id, name`). Matching Profile IDs will update their name; new IDs will be inserted.
                </p>
              </div>
              <button
                onClick={() => setShowCsvModal(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleImportCsvSubmit} className="mt-4 space-y-4">
              <textarea
                rows={8}
                value={csvText}
                onChange={(e) => setCsvText(e.target.value)}
                placeholder={`Id,Name\n00e8b000000SysAdmA,System Administrator\n00e8b000001SalesRp,Sales Representative\n00e8b000002SuppAgt,Support Agent`}
                className="w-full rounded-xl border border-slate-200 bg-slate-50 p-3 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
              />

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCsvModal(false)}
                  className="rounded-lg border border-slate-200 px-3.5 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={importing}
                  className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 disabled:opacity-50"
                >
                  {importing ? 'Importing...' : 'Import & Upsert Profiles'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// # SALESFORCE -> ## OBJECTS
// ============================================================================
export function SalesforceObjectsView({
  objects,
  savedFolderPath,
  apiFetch,
  onRefresh,
  onShowToast,
}: {
  objects: SalesforceObject[];
  savedFolderPath: string;
  apiFetch: <T = any>(url: string, options?: RequestInit) => Promise<T>;
  onRefresh: () => Promise<void>;
  onShowToast: (msg: string, isError?: boolean) => void;
}) {
  const [search, setSearch] = useState('');
  const [localFolderPath, setLocalFolderPath] = useState(savedFolderPath || '');
  const [syncingFolder, setSyncingFolder] = useState(false);
  const [uploadingBrowserFolder, setUploadingBrowserFolder] = useState(false);

  // Manual Object addition
  const [showAddModal, setShowAddModal] = useState(false);
  const [manualObjName, setManualObjName] = useState('');
  const [manualObjLabel, setManualObjLabel] = useState('');
  const [manualFieldsCsv, setManualFieldsCsv] = useState(
    'Id, Name, Status__c, OwnerId'
  );

  // Selected Object for inspecting/toggling its fields
  const [selectedObjName, setSelectedObjName] = useState<string | null>(null);
  const folderInputRef = useRef<HTMLInputElement | null>(null);

  const selectedObject =
    objects.find((o) => o.objectName === selectedObjName) || null;

  const filtered = objects.filter(
    (o) =>
      !search.trim() ||
      o.objectName.toLowerCase().includes(search.toLowerCase()) ||
      o.label.toLowerCase().includes(search.toLowerCase())
  );

  // Option 1: Browser Directory Picker (`webkitdirectory`)
  const handleBrowserDirectoryPick = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const fileList = e.target.files;
    if (!fileList || fileList.length === 0) return;

    setUploadingBrowserFolder(true);
    try {
      const xmlFiles: Array<{ relativePath: string; content: string }> = [];
      for (let i = 0; i < fileList.length; i++) {
        const f = fileList[i];
        const rel = (f as any).webkitRelativePath || f.name;
        if (
          f.name.endsWith('.xml') ||
          f.name.endsWith('.object') ||
          f.name.endsWith('.field')
        ) {
          const text = await f.text();
          xmlFiles.push({ relativePath: rel, content: text });
        }
      }

      if (xmlFiles.length === 0) {
        onShowToast(
          'No .object-meta.xml, .field-meta.xml, or .object files found in that directory.',
          true
        );
        return;
      }

      const res = await apiFetch<{
        summary: { objectsImported: number; fieldsImported: number };
      }>('/api/admin/objects/import-sfdx-files', {
        method: 'POST',
        body: JSON.stringify({ files: xmlFiles }),
      });

      await onRefresh();
      onShowToast(
        `Imported ${res.summary.objectsImported} Objects and ${res.summary.fieldsImported} Fields from folder`
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setUploadingBrowserFolder(false);
      e.target.value = '';
    }
  };

  // Option 2: Sync from Local Server Path
  const handleLocalPathSync = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!localFolderPath.trim()) return;
    setSyncingFolder(true);
    try {
      const res = await apiFetch<{
        summary: {
          objectsImported: number;
          fieldsImported: number;
          resolvedPath: string;
        };
      }>('/api/admin/objects/import-local-folder', {
        method: 'POST',
        body: JSON.stringify({ folderPath: localFolderPath.trim() }),
      });
      await onRefresh();
      onShowToast(
        `Synced ${res.summary.objectsImported} Objects (${res.summary.fieldsImported} Fields) from ${res.summary.resolvedPath}`
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    } finally {
      setSyncingFolder(false);
    }
  };

  // Option 3: Manual Object + Fields creation
  const handleManualAddObject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualObjName.trim()) return;
    try {
      const fields = manualFieldsCsv
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((fn) => ({
          fieldName: fn,
          label: fn,
          fieldType: fn === 'Id' ? 'Id' : 'Text',
          isCustom: fn.endsWith('__c'),
          required: fn === 'Id',
          enabled: true,
        }));

      await apiFetch('/api/admin/objects', {
        method: 'POST',
        body: JSON.stringify({
          objectName: manualObjName.trim(),
          label: manualObjLabel.trim() || manualObjName.trim(),
          fields,
        }),
      });
      await onRefresh();
      setShowAddModal(false);
      setManualObjName('');
      setManualObjLabel('');
      onShowToast(`Added Object "${manualObjName.trim()}"`);
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleToggleObject = async (objectName: string, enabled: boolean) => {
    try {
      await apiFetch(
        `/api/admin/objects/${encodeURIComponent(objectName)}/toggle`,
        {
          method: 'PUT',
          body: JSON.stringify({ enabled }),
        }
      );
      await onRefresh();
      onShowToast(
        `${enabled ? 'Enabled' : 'Disabled'} Object "${objectName}"`
      );
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleToggleField = async (
    objectName: string,
    fieldName: string,
    enabled: boolean
  ) => {
    try {
      await apiFetch(
        `/api/admin/objects/${encodeURIComponent(
          objectName
        )}/fields/${encodeURIComponent(fieldName)}/toggle`,
        {
          method: 'PUT',
          body: JSON.stringify({ enabled }),
        }
      );
      await onRefresh();
    } catch (err: any) {
      onShowToast(err.message, true);
    }
  };

  const handleDeleteObject = async (objectName: string) => {
    try {
      await apiFetch(`/api/admin/objects/${encodeURIComponent(objectName)}`, {
        method: 'DELETE',
      });
      if (selectedObjName === objectName) setSelectedObjName(null);
      await onRefresh();
      onShowToast(`Deleted Object "${objectName}"`);
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
            Salesforce Objects & Fields
          </h2>
          <p className="text-xs text-slate-500">
            Import your Salesforce DX `force-app/main/default/objects` directory to load objects and fields, then toggle which objects and fields are active.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Hidden Directory Input for SFDX `objects/` folder */}
          <input
            ref={(el) => {
              folderInputRef.current = el;
              if (el) {
                el.setAttribute('webkitdirectory', '');
                el.setAttribute('directory', '');
              }
            }}
            type="file"
            multiple
            onChange={handleBrowserDirectoryPick}
            className="hidden"
          />

          <button
            type="button"
            disabled={uploadingBrowserFolder}
            onClick={() => folderInputRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-semibold text-white shadow-2xs transition hover:bg-indigo-700 disabled:opacity-50"
          >
            <FolderOpen className="h-3.5 w-3.5" />
            {uploadingBrowserFolder
              ? 'Reading Folder...'
              : 'Select SFDX `objects/` Folder'}
          </button>

          <button
            type="button"
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-2xs transition hover:bg-slate-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Object Manually
          </button>
        </div>
      </div>

      {/* Local SFDX Path Sync Bar */}
      <Card className="p-3.5">
        <form
          onSubmit={handleLocalPathSync}
          className="flex flex-col gap-2.5 sm:flex-row sm:items-center"
        >
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-700">
            <HardDrive className="h-4 w-4 text-indigo-600 shrink-0" />
            <span className="whitespace-nowrap">Local SFDX Folder Path:</span>
          </div>
          <input
            type="text"
            value={localFolderPath}
            onChange={(e) => setLocalFolderPath(e.target.value)}
            placeholder="/Users/you/my-sfdx-project/force-app/main/default/objects"
            className="flex-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none"
          />
          <button
            type="submit"
            disabled={syncingFolder}
            className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-slate-800 disabled:opacity-50"
          >
            {syncingFolder ? 'Syncing...' : 'Sync from Local Path'}
          </button>
        </form>
      </Card>

      {/* Main Split Grid: Objects Table (Left) + Field Toggles (Right when selected) */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        <Card
          className={`overflow-hidden ${
            selectedObject ? 'lg:col-span-7' : 'lg:col-span-12'
          }`}
        >
          <div className="flex items-center justify-between border-b border-slate-200/80 bg-slate-50/60 px-4 py-2.5">
            <span className="text-xs font-bold text-slate-700">
              Objects ({filtered.filter((o) => o.enabled).length} enabled /{' '}
              {filtered.length} total)
            </span>
            <div className="relative">
              <Search className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search objects..."
                className="w-52 rounded-lg border border-slate-200 bg-white py-1 pr-2.5 pl-8 text-xs text-slate-800 focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200/80 bg-slate-50/40 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="py-2.5 pr-3 pl-4">Enabled</th>
                  <th className="px-3 py-2.5">Object API Name</th>
                  <th className="px-3 py-2.5">Label</th>
                  <th className="px-3 py-2.5">Fields</th>
                  <th className="py-2.5 pr-4 pl-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filtered.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      className="py-10 text-center text-xs text-slate-400"
                    >
                      No Salesforce Objects imported yet. Click{' '}
                      <span className="font-semibold text-slate-600">
                        Select SFDX `objects/` Folder
                      </span>{' '}
                      or enter a local folder path above.
                    </td>
                  </tr>
                ) : (
                  filtered.map((obj) => {
                    const isSelected =
                      selectedObject?.objectName === obj.objectName;
                    return (
                      <tr
                        key={obj.objectName}
                        className={`transition-colors ${
                          isSelected
                            ? 'bg-indigo-50/60'
                            : 'hover:bg-slate-50/80'
                        } ${!obj.enabled ? 'opacity-60' : ''}`}
                      >
                        <td className="py-2.5 pr-3 pl-4">
                          <Switch
                            checked={obj.enabled}
                            onCheckedChange={(val) =>
                              handleToggleObject(obj.objectName, val)
                            }
                          />
                        </td>
                        <td className="px-3 py-2.5 font-mono font-bold text-slate-900">
                          {obj.objectName}
                        </td>
                        <td className="px-3 py-2.5 text-slate-700">
                          {obj.label}
                        </td>
                        <td className="px-3 py-2.5">
                          <Badge variant={obj.enabled ? 'indigo' : 'slate'}>
                            {obj.enabledFieldCount} / {obj.fieldCount} fields
                          </Badge>
                        </td>
                        <td className="py-2.5 pr-4 pl-3 text-right">
                          <div className="inline-flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                setSelectedObjName(
                                  isSelected ? null : obj.objectName
                                )
                              }
                              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-semibold text-slate-700 hover:border-indigo-200 hover:text-indigo-600"
                            >
                              <SlidersHorizontal className="h-3 w-3" />
                              <span>Fields</span>
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDeleteObject(obj.objectName)}
                              className="rounded-md p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600"
                              title="Delete Object"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Right Field Inspector Panel */}
        {selectedObject && (
          <Card className="flex flex-col overflow-hidden lg:col-span-5">
            <div className="flex items-center justify-between border-b border-slate-200/80 bg-slate-50/70 px-4 py-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-indigo-600">
                    {selectedObject.objectName}
                  </span>
                  <Badge variant="slate">
                    {selectedObject.fields.length} Fields
                  </Badge>
                </div>
                <p className="text-[11px] text-slate-500">
                  Toggle which fields of `{selectedObject.objectName}` are exposed to Access Groups.
                </p>
              </div>
              <button
                onClick={() => setSelectedObjName(null)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-200/60 hover:text-slate-700"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="max-h-[460px] divide-y divide-slate-100 overflow-y-auto">
              {selectedObject.fields.map((f) => (
                <div
                  key={f.fieldName}
                  className="flex items-center justify-between px-4 py-2.5 text-xs hover:bg-slate-50"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-slate-900">
                        {f.fieldName}
                      </span>
                      <span className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
                        {f.fieldType}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500">{f.label}</p>
                  </div>
                  <Switch
                    checked={f.enabled}
                    onCheckedChange={(val) =>
                      handleToggleField(
                        selectedObject.objectName,
                        f.fieldName,
                        val
                      )
                    }
                  />
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>

      {/* Manual Add Object Modal */}
      {showAddModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 backdrop-blur-[1px]"
          onClick={() => setShowAddModal(false)}
        >
          <div
            className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-slate-900">
                Add Salesforce Object Manually
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="rounded-lg p-1 text-slate-400 hover:bg-slate-100"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleManualAddObject} className="mt-4 space-y-3.5">
              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Object API Name
                </label>
                <input
                  type="text"
                  required
                  value={manualObjName}
                  onChange={(e) => setManualObjName(e.target.value)}
                  placeholder="e.g. Account, Case, Change_Request__c"
                  className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Display Label
                </label>
                <input
                  type="text"
                  value={manualObjLabel}
                  onChange={(e) => setManualObjLabel(e.target.value)}
                  placeholder="e.g. Customer Account"
                  className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-900 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700">
                  Fields (comma-separated API names)
                </label>
                <textarea
                  rows={3}
                  value={manualFieldsCsv}
                  onChange={(e) => setManualFieldsCsv(e.target.value)}
                  className="mt-1 w-full rounded-lg border border-slate-200 p-2.5 font-mono text-xs text-slate-900 focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700"
                >
                  Save Object
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
