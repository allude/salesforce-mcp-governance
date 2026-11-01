'use client';

import React, { useState, useEffect, useRef } from 'react';
import { portalAuditResult } from './portalAudit';
import type {
  SalesforceProfile,
  SalesforceObject,
  SalesforceObjectField,
  AccessGroup,
  ProfileGroupMapping,
  SalesforceConnectionSettings,
  McpActionType,
  GroupObjectPermission,
} from '@/types/governance';
import {
  MCP_TOOL_CATALOG,
  isSensitiveField,
} from '@/components/ui/primitives';

export type FlyoutType =
  | 'profile'
  | 'newprofile'
  | 'import'
  | 'object'
  | 'sync'
  | 'group'
  | 'traffic'
  | 'audit'
  | 'simulator';

export interface FlyoutState {
  type: FlyoutType;
  data?: any;
}

interface FlyoutDrawerProps {
  flyout: FlyoutState | null;
  onClose: () => void;
  onOpenFlyout: (next: FlyoutState) => void;
  onNavigateView: (view: string, filterUser?: string) => void;
  profiles: SalesforceProfile[];
  objects: SalesforceObject[];
  groups: AccessGroup[];
  mappings: ProfileGroupMapping[];
  sfSettings: SalesforceConnectionSettings | null;
  onUpsertProfile: (id: string, name: string) => Promise<void>;
  onDeleteProfile: (id: string) => Promise<void>;
  onImportCsv: (csvText: string) => Promise<void>;
  onToggleProfileGroup: (profileId: string, groupId: string) => Promise<void>;
  onToggleObject: (objectName: string, enabled: boolean) => Promise<void>;
  onToggleField: (
    objectName: string,
    fieldName: string,
    enabled: boolean
  ) => Promise<void>;
  onBulkToggleFields: (objectName: string, enabled: boolean) => Promise<void>;
  onSyncSfdxPath: (folderPath: string) => Promise<void>;
  onSyncUploadedFiles: (
    files: Array<{ relativePath: string; content: string }>
  ) => Promise<void>;
  onOpenOrgObjectCatalogModal?: () => void;
  onSaveGroup: (group: {
    id?: string;
    name: string;
    description: string;
    allowedActions: McpActionType[];
    objectPermissions: GroupObjectPermission[];
  }) => Promise<AccessGroup | void>;
  onDeleteGroup: (groupId: string) => Promise<void>;
  onTestMcpCall: (payload: {
    profileId: string;
    toolName: string;
    targetObject: string;
    username?: string;
    samplePayload?: Record<string, unknown>;
  }) => Promise<any>;
  onRefreshWorkspace: () => Promise<void>;
  notify: (msg: string) => void;
}

const SAMPLE_CSV = `ProfileId,ProfileName
00e5g000001A9xLAAS,System Administrator
00e5g000001B2k9AAC,Enterprise Sales AE
00e5g000001L4rXAAS,Channel Partner Manager
00e5g000001M8tYAAS,Field Service Technician
00e5g000001N2vZAAS,Legal & Compliance Reviewer`;

export function FlyoutDrawer({
  flyout,
  onClose,
  onOpenFlyout,
  onNavigateView,
  profiles,
  objects,
  groups,
  mappings,
  sfSettings,
  onUpsertProfile,
  onDeleteProfile,
  onImportCsv,
  onToggleProfileGroup,
  onToggleObject,
  onToggleField,
  onBulkToggleFields,
  onSyncSfdxPath,
  onSyncUploadedFiles,
  onOpenOrgObjectCatalogModal,
  onSaveGroup,
  onDeleteGroup,
  onTestMcpCall,
  onRefreshWorkspace,
  notify,
}: FlyoutDrawerProps) {
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);

  // Profile state
  const [profNameEdit, setProfNameEdit] = useState('');
  const [newProfId, setNewProfId] = useState('00e5g000001P5xAAAS');
  const [newProfName, setNewProfName] = useState('');

  // Import CSV state
  const [csvText, setCsvText] = useState('');

  // Object drawer state
  const [fieldQuery, setFieldQuery] = useState('');

  // Sync drawer state
  const [sfdxPath, setSfdxPath] = useState(
    './sfdx-project/force-app/main/default/objects'
  );
  const [pendingUploadFiles, setPendingUploadFiles] = useState<
    Array<{ relativePath: string; content: string }>
  >([]);
  const [uploadPreview, setUploadPreview] = useState<
    Array<{
      objectName: string;
      label: string;
      custom: boolean;
      fieldCount: number;
      isExisting: boolean;
    }>
  >([]);
  const folderInputRef = useRef<HTMLInputElement | null>(null);

  // Group drawer state
  const [grpDraft, setGrpDraft] = useState<{
    id?: string;
    name: string;
    description: string;
    allowedActions: McpActionType[];
    objectPermissions: GroupObjectPermission[];
  } | null>(null);
  const [expandedObj, setExpandedObj] = useState<string | null>(null);

  // Simulator drawer state
  const [simProfileId, setSimProfileId] = useState('');
  const [simUsername, setSimUsername] = useState('Jordan Lee');
  const [simTool, setSimTool] = useState<McpActionType>('soql_query');
  const [simObject, setSimObject] = useState('Opportunity');
  const [simResult, setSimResult] = useState<any>(null);

  useEffect(() => {
    setConfirmDelete(false);
    setFieldQuery('');
    if (!flyout) return;

    if (flyout.type === 'profile' && flyout.data) {
      const liveProf =
        profiles.find((p) => p.id === flyout.data.id) || flyout.data;
      setProfNameEdit(liveProf.name);
    } else if (flyout.type === 'newprofile') {
      const suffix = Math.random().toString(36).substring(2, 6).toUpperCase();
      setNewProfId(`00e5g000001${suffix}AAS`);
      setNewProfName('');
    } else if (flyout.type === 'group' && flyout.data) {
      const liveGrp =
        groups.find((g) => g.id === flyout.data.id) || flyout.data;
      setGrpDraft({
        id: liveGrp.id,
        name: liveGrp.name || '',
        description: liveGrp.description || '',
        allowedActions: [...(liveGrp.allowedActions || [])],
        objectPermissions: (liveGrp.objectPermissions || []).map(
          (op: GroupObjectPermission) => ({
            ...op,
            allowedFields: [...(op.allowedFields || [])],
          })
        ),
      });
    } else if (flyout.type === 'simulator') {
      const initProf =
        flyout.data?.profileId || profiles[0]?.id || '00e5g000001B2k9AAC';
      setSimProfileId(initProf);
      if (flyout.data?.username) setSimUsername(flyout.data.username);
      if (flyout.data?.toolName) setSimTool(flyout.data.toolName);
      if (flyout.data?.targetObject && flyout.data.targetObject !== '*') {
        setSimObject(flyout.data.targetObject);
      } else if (objects[0]?.objectName) {
        setSimObject(objects[0].objectName);
      }
      setSimResult(null);
    }
  }, [flyout?.type, flyout?.data?.id, flyout?.data?.objectName]);

  useEffect(() => {
    if (!flyout) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [flyout, onClose]);

  if (!flyout) return null;

  const getProfileGroupIds = (profileId: string): string[] => {
    const found = mappings.find((m) => m.profileId === profileId);
    return found ? found.groupIds : [];
  };

  const liveProfile: SalesforceProfile | null =
    flyout.type === 'profile'
      ? profiles.find((p) => p.id === flyout.data?.id) || flyout.data
      : null;

  const liveObject: SalesforceObject | null =
    flyout.type === 'object'
      ? objects.find((o) => o.objectName === flyout.data?.objectName) ||
        flyout.data
      : null;

  const liveGroup: AccessGroup | null =
    flyout.type === 'group'
      ? groups.find((g) => g.id === flyout.data?.id) || flyout.data
      : null;

  const computeEffectiveAccess = (profileId: string) => {
    const gIds = getProfileGroupIds(profileId);
    const assignedGroups = groups.filter((g) => gIds.includes(g.id));
    const actions = new Set<McpActionType>();
    const objMap: Record<
      string,
      { R: boolean; C: boolean; U: boolean; D: boolean }
    > = {};

    for (const g of assignedGroups) {
      (g.allowedActions || []).forEach((a) => actions.add(a));
      for (const op of g.objectPermissions || []) {
        const objCfg = objects.find((o) => o.objectName === op.objectName);
        if (objCfg && !objCfg.enabled) continue;
        if (!objMap[op.objectName]) {
          objMap[op.objectName] = { R: false, C: false, U: false, D: false };
        }
        if (op.canRead) objMap[op.objectName].R = true;
        if (op.canCreate) objMap[op.objectName].C = true;
        if (op.canUpdate) objMap[op.objectName].U = true;
        if (op.canDelete) objMap[op.objectName].D = true;
      }
    }
    return {
      assignedGroups,
      actions: Array.from(actions),
      objects: objMap,
    };
  };

  const parseCsvRows = (raw: string) => {
    return raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .filter((l, idx) => !(idx === 0 && /profile\s*id/i.test(l)))
      .map((l) => {
        const parts = l
          .split(',')
          .map((s) => s.trim().replace(/^"|"$/g, ''));
        const id = parts[0] || '';
        const name = parts.slice(1).join(', ') || '';
        const valid = /^[a-zA-Z0-9]{15}([a-zA-Z0-9]{3})?$/.test(id) && !!name;
        const existing = profiles.find((p) => p.id === id);
        const status = !valid
          ? 'invalid'
          : !existing
            ? 'new'
            : existing.name !== name
              ? 'update'
              : 'unchanged';
        return { id, name, status };
      });
  };

  const handleFolderSelect = async (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    const collected: Array<{ relativePath: string; content: string }> = [];
    const byObj: Record<
      string,
      {
        objectName: string;
        label: string;
        custom: boolean;
        fields: Set<string>;
      }
    > = {};

    for (const f of Array.from(fileList)) {
      const rel = (f as any).webkitRelativePath || f.name;
      if (
        !rel.endsWith('.object-meta.xml') &&
        !rel.endsWith('.field-meta.xml') &&
        !rel.endsWith('.object')
      ) {
        continue;
      }
      const text = await f.text();
      collected.push({ relativePath: rel, content: text });

      const parts = rel.split('/');
      const objIdx = parts.indexOf('objects');
      const objName =
        objIdx >= 0 && parts[objIdx + 1]
          ? parts[objIdx + 1]
          : parts[0].replace(/\.object(-meta\.xml)?$/, '');
      if (!objName) continue;

      if (!byObj[objName]) {
        byObj[objName] = {
          objectName: objName,
          label: objName.replace(/__c$/, '').replace(/_/g, ' '),
          custom: objName.endsWith('__c'),
          fields: new Set(['Id', 'Name']),
        };
      }
      if (rel.endsWith('.field-meta.xml')) {
        const fnMatch =
          text.match(/<fullName>([^<]+)<\/fullName>/) ||
          rel.match(/([^/]+)\.field-meta\.xml$/);
        if (fnMatch && fnMatch[1]) {
          byObj[objName].fields.add(fnMatch[1]);
        }
      }
    }

    setPendingUploadFiles(collected);
    setUploadPreview(
      Object.values(byObj).map((item) => ({
        objectName: item.objectName,
        label: item.label,
        custom: item.custom,
        fieldCount: item.fields.size,
        isExisting: objects.some((o) => o.objectName === item.objectName),
      }))
    );
  };

  const loadSampleSfdxBundle = () => {
    const sampleFiles = [
      {
        relativePath:
          'objects/Contract__c/Contract__c.object-meta.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
  <label>Enterprise Contract</label>
  <pluralLabel>Enterprise Contracts</pluralLabel>
  <deploymentStatus>Deployed</deploymentStatus>
</CustomObject>`,
      },
      {
        relativePath:
          'objects/Contract__c/fields/ARR_Value__c.field-meta.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
  <fullName>ARR_Value__c</fullName>
  <label>ARR Value</label>
  <type>Currency</type>
</CustomField>`,
      },
      {
        relativePath:
          'objects/Contract__c/fields/Auto_Renew__c.field-meta.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
  <fullName>Auto_Renew__c</fullName>
  <label>Auto Renew</label>
  <type>Checkbox</type>
</CustomField>`,
      },
      {
        relativePath:
          'objects/Subscription__c/Subscription__c.object-meta.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
  <label>Subscription</label>
  <pluralLabel>Subscriptions</pluralLabel>
  <deploymentStatus>Deployed</deploymentStatus>
</CustomObject>`,
      },
      {
        relativePath:
          'objects/Subscription__c/fields/Billing_Cycle__c.field-meta.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
  <fullName>Billing_Cycle__c</fullName>
  <label>Billing Cycle</label>
  <type>Picklist</type>
</CustomField>`,
      },
    ];
    setPendingUploadFiles(sampleFiles);
    setUploadPreview([
      {
        objectName: 'Contract__c',
        label: 'Enterprise Contract',
        custom: true,
        fieldCount: 4,
        isExisting: objects.some((o) => o.objectName === 'Contract__c'),
      },
      {
        objectName: 'Subscription__c',
        label: 'Subscription',
        custom: true,
        fieldCount: 3,
        isExisting: objects.some((o) => o.objectName === 'Subscription__c'),
      },
    ]);
  };

  const toggleGroupObjectCrud = (
    objectName: string,
    opKey: 'canRead' | 'canCreate' | 'canUpdate' | 'canDelete'
  ) => {
    if (!grpDraft) return;
    const existingIdx = grpDraft.objectPermissions.findIndex(
      (p) => p.objectName === objectName
    );
    const objMeta = objects.find((o) => o.objectName === objectName);
    const allEnabledFieldNames = objMeta
      ? objMeta.fields
          .filter((f: SalesforceObjectField) => f.enabled)
          .map((f: SalesforceObjectField) => f.fieldName)
      : ['Id', 'Name'];

    const current: GroupObjectPermission =
      existingIdx >= 0
        ? { ...grpDraft.objectPermissions[existingIdx] }
        : {
            objectName,
            canRead: false,
            canCreate: false,
            canUpdate: false,
            canDelete: false,
            allowedFields: allEnabledFieldNames,
          };

    const nextVal = !current[opKey];
    current[opKey] = nextVal;

    if (nextVal && opKey !== 'canRead') {
      current.canRead = true;
    }
    if (!nextVal && opKey === 'canRead') {
      current.canCreate = false;
      current.canUpdate = false;
      current.canDelete = false;
    }

    const nextPerms = [...grpDraft.objectPermissions];
    if (
      !current.canRead &&
      !current.canCreate &&
      !current.canUpdate &&
      !current.canDelete
    ) {
      if (existingIdx >= 0) nextPerms.splice(existingIdx, 1);
    } else if (existingIdx >= 0) {
      nextPerms[existingIdx] = current;
    } else {
      nextPerms.push(current);
    }

    setGrpDraft({
      ...grpDraft,
      objectPermissions: nextPerms,
    });
  };

  const toggleGroupObjectField = (objectName: string, fieldName: string) => {
    if (!grpDraft) return;
    const idx = grpDraft.objectPermissions.findIndex(
      (p) => p.objectName === objectName
    );
    if (idx < 0) return;
    const perm = { ...grpDraft.objectPermissions[idx] };
    const set = new Set(perm.allowedFields || []);
    if (set.has(fieldName)) set.delete(fieldName);
    else set.add(fieldName);
    perm.allowedFields = Array.from(set);
    const nextPerms = [...grpDraft.objectPermissions];
    nextPerms[idx] = perm;
    setGrpDraft({ ...grpDraft, objectPermissions: nextPerms });
  };

  const setAllGroupObjectFields = (objectName: string, enableAll: boolean) => {
    if (!grpDraft) return;
    const idx = grpDraft.objectPermissions.findIndex(
      (p) => p.objectName === objectName
    );
    if (idx < 0) return;
    const objMeta = objects.find((o) => o.objectName === objectName);
    const perm = { ...grpDraft.objectPermissions[idx] };
    perm.allowedFields =
      enableAll && objMeta
        ? objMeta.fields
            .filter((f: SalesforceObjectField) => f.enabled)
            .map((f: SalesforceObjectField) => f.fieldName)
        : [];
    const nextPerms = [...grpDraft.objectPermissions];
    nextPerms[idx] = perm;
    setGrpDraft({ ...grpDraft, objectPermissions: nextPerms });
  };

  const handleRunBurst = async () => {
    setBusy(true);
    try {
      const sampleCalls: Array<{
        profileId: string;
        username: string;
        toolName: McpActionType;
        targetObject: string;
      }> = [
        {
          profileId: profiles[0]?.id || '00e5g000001A9xLAAS',
          username: 'Jordan Lee',
          toolName: 'soql_query',
          targetObject: 'Opportunity',
        },
        {
          profileId: profiles[1]?.id || profiles[0]?.id || '00e5g000001B2k9AAC',
          username: 'Maya Patel',
          toolName: 'update_record',
          targetObject: 'Account',
        },
        {
          profileId: profiles[2]?.id || profiles[0]?.id || '00e5g000001D8pRAAU',
          username: 'Devon Brooks',
          toolName: 'get_record',
          targetObject: 'Case',
        },
        {
          profileId: profiles[1]?.id || profiles[0]?.id || '00e5g000001B2k9AAC',
          username: 'Hannah Kim',
          toolName: 'delete_record',
          targetObject: 'Account',
        },
        {
          profileId: profiles[3]?.id || profiles[0]?.id || '00e5g000001C4mQAAQ',
          username: 'Carlos Reyes',
          toolName: 'describe_object',
          targetObject: 'Opportunity',
        },
        {
          profileId:
            profiles[profiles.length - 1]?.id || '00e5g000001J0yVAAS',
          username: 'Priya Nair',
          toolName: 'soql_query',
          targetObject: 'Contact',
        },
      ];
      let lastRes = null;
      for (const call of sampleCalls) {
        lastRes = await onTestMcpCall(call);
      }
      setSimResult(lastRes);
      await onRefreshWorkspace();
      notify('Simulated 6 Copilot MCP traffic events');
    } catch {
      // The error toast is already showing; stay here so the admin can retry.
    } finally {
      setBusy(false);
    }
  };

  let title = '';
  let subtitle = '';
  if (flyout.type === 'profile' && liveProfile) {
    title = liveProfile.name;
    subtitle = `Salesforce Profile · ${liveProfile.id}`;
  } else if (flyout.type === 'newprofile') {
    title = 'Add profile';
    subtitle = 'Register a Salesforce Profile ID with the MCP server';
  } else if (flyout.type === 'import') {
    title = 'Import profiles CSV';
    subtitle = 'Bulk upsert Salesforce Profile IDs and names';
  } else if (flyout.type === 'object' && liveObject) {
    title = liveObject.objectName;
    subtitle = `${liveObject.label} · ${
      liveObject.isCustom ? 'Custom' : 'Standard'
    } · ${liveObject.fields.length} fields`;
  } else if (flyout.type === 'sync') {
    title = 'Sync Salesforce objects';
    subtitle = 'SFDX XML folder · Local server path · Salesforce Org Pull';
  } else if (flyout.type === 'group' && grpDraft) {
    title = grpDraft.name || 'New Access Group';
    subtitle = `Access group · ${grpDraft.id || 'unsaved'}`;
  } else if (flyout.type === 'traffic' && flyout.data) {
    title = `${flyout.data.toolName}(${flyout.data.targetObject})`;
    subtitle = `MCP traffic event · ${flyout.data.id}`;
  } else if (flyout.type === 'audit' && flyout.data) {
    title = `${flyout.data.action} · ${flyout.data.target}`;
    subtitle = `Portal audit event · ${flyout.data.id}`;
  } else if (flyout.type === 'simulator') {
    title = 'Live MCP Policy Simulator';
    subtitle = 'Evaluate Profile-to-Group RBAC & generate Copilot test traffic';
  }

  const csvRows = flyout.type === 'import' ? parseCsvRows(csvText) : [];
  const validCsvRows = csvRows.filter(
    (r) => r.status === 'new' || r.status === 'update'
  );

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="fly" aria-label="Details drawer">
        <div className="fly-h">
          <div>
            <div className="fly-t">{title}</div>
            <div className="fly-s">{subtitle}</div>
          </div>
          <button
            className="btn gh sm"
            onClick={onClose}
            title="Close (Esc)"
          >
            ✕
          </button>
        </div>

        <div className="fly-b">
          {/* 1. PROFILE DRAWER */}
          {flyout.type === 'profile' && liveProfile && (
            <>
              <div className="sec">
                <div className="fld">
                  <label>Profile name</label>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <input
                      className="inp"
                      value={profNameEdit}
                      onChange={(e) => setProfNameEdit(e.target.value)}
                    />
                    {profNameEdit.trim() &&
                      profNameEdit.trim() !== liveProfile.name && (
                        <button
                          className="btn pri sm"
                          disabled={busy}
                          onClick={async () => {
                            setBusy(true);
                            try {
                              await onUpsertProfile(
                                liveProfile.id,
                                profNameEdit.trim()
                              );
                            } catch {
                              // The error toast is already showing; stay here so the admin can retry.
                            } finally {
                              setBusy(false);
                            }
                          }}
                        >
                          Save
                        </button>
                      )}
                  </div>
                </div>
                <dl className="kv">
                  <dt>Profile ID</dt>
                  <dd className="mono">{liveProfile.id}</dd>
                  <dt>Org status</dt>
                  <dd>
                    {liveProfile.missingInOrg ? (
                      <span className="tag warn">Missing in Org</span>
                    ) : (
                      <span className="tag ok">Active</span>
                    )}
                  </dd>
                  <dt>Updated</dt>
                  <dd className="mono">
                    {liveProfile.updatedAt?.slice(0, 10) || '—'}
                  </dd>
                </dl>
              </div>

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">Group memberships</span>
                  <span className="mono" style={{ color: 'var(--t3)' }}>
                    {getProfileGroupIds(liveProfile.id).length} assigned
                  </span>
                </div>
                {groups.length === 0 ? (
                  <div
                    className="empty"
                    style={{
                      padding: 14,
                      border: '1px solid var(--bd)',
                      borderRadius: 6,
                    }}
                  >
                    No Access Groups exist yet. Create one in Access Matrix
                    &rarr; Groups.
                  </div>
                ) : (
                  <div className="chk-list">
                    {groups.map((g) => {
                      const on = getProfileGroupIds(liveProfile.id).includes(
                        g.id
                      );
                      return (
                        <div className="chk-row" key={g.id}>
                          <div>
                            <div style={{ fontWeight: 500 }}>{g.name}</div>
                            <div
                              style={{ fontSize: 11, color: 'var(--t3)' }}
                            >
                              {g.description}
                            </div>
                          </div>
                          <button
                            type="button"
                            className={`sw ${on ? 'on' : ''}`}
                            onClick={() =>
                              onToggleProfileGroup(liveProfile.id, g.id)
                            }
                          />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {(() => {
                const eff = computeEffectiveAccess(liveProfile.id);
                const objEntries = Object.entries(eff.objects);
                return (
                  <div className="sec">
                    <div className="sec-h">
                      <span className="sec-t">
                        Effective access (union of assigned groups)
                      </span>
                    </div>
                    {eff.actions.length === 0 && objEntries.length === 0 ? (
                      <div
                        className="empty"
                        style={{
                          padding: 16,
                          border: '1px solid var(--bd)',
                          borderRadius: 6,
                        }}
                      >
                        No groups assigned — all Copilot MCP calls from this
                        profile are denied.
                      </div>
                    ) : (
                      <>
                        <div style={{ marginBottom: 10 }}>
                          <div
                            style={{
                              fontSize: 11,
                              color: 'var(--t3)',
                              marginBottom: 5,
                            }}
                          >
                            Allowed MCP actions ({eff.actions.length})
                          </div>
                          <div
                            style={{
                              display: 'flex',
                              gap: 4,
                              flexWrap: 'wrap',
                            }}
                          >
                            {eff.actions.map((a) => (
                              <span
                                key={a}
                                className={`tag mono ${
                                  a === 'delete_record' ? 'err' : 'acc'
                                }`}
                              >
                                {a}
                              </span>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div
                            style={{
                              fontSize: 11,
                              color: 'var(--t3)',
                              marginBottom: 5,
                            }}
                          >
                            Object access ({objEntries.length})
                          </div>
                          <div className="chk-list">
                            {objEntries.map(([objName, c]) => (
                              <div className="chk-row" key={objName}>
                                <span className="mono">{objName}</span>
                                <span className="crud">
                                  {(['R', 'C', 'U', 'D'] as const).map((k) => (
                                    <span
                                      key={k}
                                      className={`cell ${
                                        c[k] ? 'on' : ''
                                      } ${k === 'D' ? 'dng' : ''}`}
                                    >
                                      {k}
                                    </span>
                                  ))}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                );
              })()}
            </>
          )}

          {/* 2. NEW PROFILE DRAWER */}
          {flyout.type === 'newprofile' && (
            <div className="sec">
              <div className="fld">
                <label>Salesforce Profile ID (15 or 18 chars)</label>
                <input
                  className="inp mono"
                  value={newProfId}
                  onChange={(e) => setNewProfId(e.target.value)}
                  placeholder="00e5g000001X9zAAAS"
                />
                <div className="hint">
                  Standard Salesforce Profile prefix is{' '}
                  <span className="mono">00e</span>.
                </div>
              </div>
              <div className="fld">
                <label>Profile name</label>
                <input
                  className="inp"
                  value={newProfName}
                  onChange={(e) => setNewProfName(e.target.value)}
                  placeholder="e.g. Regional Sales Director"
                />
              </div>
            </div>
          )}

          {/* 3. IMPORT CSV DRAWER */}
          {flyout.type === 'import' && (
            <>
              <div className="sec">
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: 8,
                    gap: 8,
                    flexWrap: 'wrap',
                  }}
                >
                  <label style={{ fontSize: 11.5, color: 'var(--t2)' }}>
                    Upload <span className="mono">.csv</span> file or paste
                    rows (<span className="mono">ProfileId,ProfileName</span>)
                  </label>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <label
                      className="btn sm"
                      style={{ cursor: 'pointer', margin: 0 }}
                    >
                      Choose .csv file
                      <input
                        type="file"
                        accept=".csv,text/csv,text/plain"
                        style={{ display: 'none' }}
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (!f) return;
                          const r = new FileReader();
                          r.onload = () => setCsvText(String(r.result || ''));
                          r.readAsText(f);
                        }}
                      />
                    </label>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() => setCsvText(SAMPLE_CSV)}
                    >
                      Load sample
                    </button>
                  </div>
                </div>
                <textarea
                  className="inp"
                  value={csvText}
                  onChange={(e) => setCsvText(e.target.value)}
                  placeholder={SAMPLE_CSV}
                />
              </div>

              {csvRows.length > 0 && (
                <div className="sec">
                  <div className="sec-h">
                    <span className="sec-t">
                      Preview ({csvRows.length} rows)
                    </span>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <span className="tag ok">
                        {csvRows.filter((r) => r.status === 'new').length} new
                      </span>
                      <span className="tag acc">
                        {csvRows.filter((r) => r.status === 'update').length}{' '}
                        renamed
                      </span>
                      <span className="tag">
                        {csvRows.filter((r) => r.status === 'unchanged').length}{' '}
                        unchanged
                      </span>
                      {csvRows.some((r) => r.status === 'invalid') && (
                        <span className="tag err">
                          {csvRows.filter((r) => r.status === 'invalid').length}{' '}
                          invalid
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="chk-list">
                    {csvRows.map((r, i) => (
                      <div className="chk-row" key={i}>
                        <div>
                          <div style={{ fontWeight: 500 }}>
                            {r.name || '—'}
                          </div>
                          <div
                            className="mono"
                            style={{ color: 'var(--t3)' }}
                          >
                            {r.id || '(missing id)'}
                          </div>
                        </div>
                        <span
                          className={`tag ${
                            r.status === 'new'
                              ? 'ok'
                              : r.status === 'update'
                                ? 'acc'
                                : r.status === 'invalid'
                                  ? 'err'
                                  : ''
                          }`}
                        >
                          {r.status}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* 4. OBJECT DRAWER */}
          {flyout.type === 'object' && liveObject && (
            <>
              <div className="sec">
                <dl className="kv">
                  <dt>Enabled for MCP</dt>
                  <dd>
                    <button
                      type="button"
                      className={`sw ${liveObject.enabled ? 'on' : ''}`}
                      onClick={() =>
                        onToggleObject(
                          liveObject.objectName,
                          !liveObject.enabled
                        )
                      }
                    />
                  </dd>
                  <dt>Label</dt>
                  <dd>{liveObject.label}</dd>
                  <dt>Category</dt>
                  <dd>
                    <span
                      className={`tag ${liveObject.isCustom ? 'pur' : ''}`}
                    >
                      {liveObject.isCustom ? 'Custom (__c)' : 'Standard'}
                    </span>
                  </dd>
                  <dt>Source path</dt>
                  <dd className="mono">{liveObject.sourcePath}</dd>
                  <dt>Org status</dt>
                  <dd>
                    {liveObject.missingInOrg ? (
                      <span className="tag warn">Missing in Org</span>
                    ) : (
                      <span className="tag ok">Present</span>
                    )}
                  </dd>
                  <dt>Last synced</dt>
                  <dd className="mono">
                    {liveObject.updatedAt?.slice(0, 16).replace('T', ' ') ||
                      '—'}
                  </dd>
                </dl>
              </div>

              {(() => {
                const usedBy = groups.filter((g) =>
                  g.objectPermissions?.some(
                    (op) =>
                      op.objectName === liveObject.objectName &&
                      (op.canRead ||
                        op.canCreate ||
                        op.canUpdate ||
                        op.canDelete)
                  )
                );
                return (
                  <div className="sec">
                    <div className="sec-h">
                      <span className="sec-t">
                        Used by groups ({usedBy.length})
                      </span>
                    </div>
                    {usedBy.length === 0 ? (
                      <div
                        className="empty"
                        style={{
                          padding: 14,
                          border: '1px solid var(--bd)',
                          borderRadius: 6,
                        }}
                      >
                        No access group grants permissions on this object yet.
                      </div>
                    ) : (
                      <div className="chk-list">
                        {usedBy.map((g) => {
                          const op = g.objectPermissions.find(
                            (p) => p.objectName === liveObject.objectName
                          );
                          return (
                            <div
                              className="chk-row"
                              key={g.id}
                              style={{ cursor: 'pointer' }}
                              onClick={() =>
                                onOpenFlyout({ type: 'group', data: g })
                              }
                            >
                              <span>{g.name}</span>
                              {op && (
                                <span className="crud">
                                  <span
                                    className={`cell ${op.canRead ? 'on' : ''}`}
                                  >
                                    R
                                  </span>
                                  <span
                                    className={`cell ${
                                      op.canCreate ? 'on' : ''
                                    }`}
                                  >
                                    C
                                  </span>
                                  <span
                                    className={`cell ${
                                      op.canUpdate ? 'on' : ''
                                    }`}
                                  >
                                    U
                                  </span>
                                  <span
                                    className={`cell ${
                                      op.canDelete ? 'on dng' : ''
                                    }`}
                                  >
                                    D
                                  </span>
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })()}

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    Fields (
                    {
                      liveObject.fields.filter(
                        (f: SalesforceObjectField) => f.enabled
                      ).length
                    }{' '}
                    of {liveObject.fields.length} enabled)
                  </span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        onBulkToggleFields(liveObject.objectName, true)
                      }
                    >
                      Enable all
                    </button>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        onBulkToggleFields(liveObject.objectName, false)
                      }
                    >
                      Disable all
                    </button>
                  </div>
                </div>
                <input
                  className="inp"
                  style={{ marginBottom: 8 }}
                  placeholder="Filter fields by API name, label, or type…"
                  value={fieldQuery}
                  onChange={(e) => setFieldQuery(e.target.value)}
                />
                <div className="chk-list" style={{ maxHeight: 330 }}>
                  {liveObject.fields
                    .filter(
                      (f: SalesforceObjectField) =>
                        !fieldQuery ||
                        f.fieldName
                          .toLowerCase()
                          .includes(fieldQuery.toLowerCase()) ||
                        f.label
                          .toLowerCase()
                          .includes(fieldQuery.toLowerCase()) ||
                        f.fieldType
                          .toLowerCase()
                          .includes(fieldQuery.toLowerCase())
                    )
                    .map((f: SalesforceObjectField) => {
                      const sens = isSensitiveField(f.fieldName, f.label);
                      return (
                        <div className="chk-row" key={f.fieldName}>
                          <div>
                            <div
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 6,
                                flexWrap: 'wrap',
                              }}
                            >
                              <span
                                className="mono"
                                style={{ fontWeight: 500 }}
                              >
                                {f.fieldName}
                              </span>
                              <span className="tag">{f.fieldType}</span>
                              {f.isCustom && (
                                <span className="tag pur">custom</span>
                              )}
                              {f.missingInOrg && (
                                <span className="tag warn">Missing in Org</span>
                              )}
                              {sens && (
                                <span
                                  className="tag warn"
                                  title="Matches PII / sensitive field heuristic"
                                >
                                  sensitive
                                </span>
                              )}
                            </div>
                            <div
                              style={{ fontSize: 11, color: 'var(--t3)' }}
                            >
                              {f.label}
                            </div>
                          </div>
                          <button
                            type="button"
                            className={`sw ${f.enabled ? 'on' : ''}`}
                            onClick={() =>
                              onToggleField(
                                liveObject.objectName,
                                f.fieldName,
                                !f.enabled
                              )
                            }
                          />
                        </div>
                      );
                    })}
                </div>
              </div>
            </>
          )}

          {/* 5. SYNC OBJECTS DRAWER */}
          {flyout.type === 'sync' && (
            <>
              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    1. Upload SFDX objects/ folder
                  </span>
                  <button
                    type="button"
                    className="btn sm"
                    onClick={loadSampleSfdxBundle}
                  >
                    Load sample SFDX preview
                  </button>
                </div>
                <input
                  ref={folderInputRef}
                  type="file"
                  style={{ display: 'none' }}
                  multiple
                  {...({ webkitdirectory: '' } as any)}
                  onChange={(e) => handleFolderSelect(e.target.files)}
                />
                <div
                  className="drop"
                  onClick={() => folderInputRef.current?.click()}
                >
                  <div style={{ fontWeight: 500, color: 'var(--tx)' }}>
                    Select local{' '}
                    <span className="mono">
                      force-app/main/default/objects
                    </span>{' '}
                    folder
                  </div>
                  <div
                    style={{ fontSize: 11.5, color: 'var(--t3)', marginTop: 3 }}
                  >
                    Parses{' '}
                    <span className="mono">*.object-meta.xml</span> and{' '}
                    <span className="mono">fields/*.field-meta.xml</span>
                  </div>
                </div>

                {uploadPreview.length > 0 && (
                  <div style={{ marginTop: 10 }}>
                    <div
                      style={{
                        fontSize: 11.5,
                        color: 'var(--t2)',
                        marginBottom: 6,
                      }}
                    >
                      Ready to merge{' '}
                      <b>{uploadPreview.length} SObjects</b> (
                      {pendingUploadFiles.length} XML files):
                    </div>
                    <div className="chk-list">
                      {uploadPreview.map((so) => (
                        <div className="chk-row" key={so.objectName}>
                          <div>
                            <span
                              className="mono"
                              style={{ fontWeight: 600 }}
                            >
                              {so.objectName}
                            </span>{' '}
                            <span
                              style={{ color: 'var(--t3)', fontSize: 11.5 }}
                            >
                              ({so.label})
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <span
                              className={`tag ${
                                so.isExisting ? 'acc' : 'ok'
                              }`}
                            >
                              {so.isExisting ? 'existing' : 'new'}
                            </span>
                            <span className="tag mono">
                              {so.fieldCount} fields
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">2. Sync from local server path</span>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    className="inp mono"
                    value={sfdxPath}
                    onChange={(e) => setSfdxPath(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={async () => {
                      setBusy(true);
                      try {
                        await onSyncSfdxPath(sfdxPath);
                        onClose();
                      } catch {
                        // The error toast is already showing; stay here so the admin can retry.
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    Sync path
                  </button>
                </div>
                <pre className="code" style={{ marginTop: 8 }}>{`curl -X POST http://localhost:3001/api/admin/objects/import-local-folder \\
  -H "Content-Type: application/json" \\
  -d '{"folderPath":"${sfdxPath}"}'`}</pre>
              </div>

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    3. Pull from connected Salesforce org
                  </span>
                  {sfSettings?.connectionStatus === 'connected' ? (
                    <span className="tag ok">
                      Connected · {sfSettings.connectedOrgId}
                    </span>
                  ) : (
                    <span className="tag warn">Not connected</span>
                  )}
                </div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 10,
                    padding: '10px 12px',
                    border: '1px solid var(--bd)',
                    borderRadius: 6,
                    background: 'var(--bg)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                      Salesforce REST <span className="mono">describeGlobal</span>{' '}
                      &amp; Field Reconciliation
                    </div>
                    <div style={{ fontSize: 11.5, color: 'var(--t3)' }}>
                      {sfSettings?.connectionStatus === 'connected'
                        ? `Authenticated as ${sfSettings.connectedUser} (${sfSettings.instanceUrl})`
                        : 'Connect your Salesforce Org via OAuth 2.0 JWT Bearer to pull live SObjects.'}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {sfSettings?.connectionStatus === 'connected' &&
                    onOpenOrgObjectCatalogModal ? (
                      <button
                        type="button"
                        className="btn pri"
                        onClick={() => {
                          onClose();
                          onOpenOrgObjectCatalogModal();
                        }}
                      >
                        Open Org Catalog
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn"
                        onClick={() => {
                          onClose();
                          onNavigateView('sf-connection');
                        }}
                      >
                        Configure JWT Connection
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* 6. GROUP DRAWER */}
          {flyout.type === 'group' && grpDraft && (
            <>
              <div className="sec">
                <div className="fld">
                  <label>Group name</label>
                  <input
                    className="inp"
                    value={grpDraft.name}
                    onChange={(e) =>
                      setGrpDraft({ ...grpDraft, name: e.target.value })
                    }
                  />
                </div>
                <div className="fld" style={{ marginBottom: 0 }}>
                  <label>Description</label>
                  <input
                    className="inp"
                    value={grpDraft.description}
                    onChange={(e) =>
                      setGrpDraft({ ...grpDraft, description: e.target.value })
                    }
                  />
                </div>
              </div>

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    MCP actions ({grpDraft.allowedActions.length} of{' '}
                    {MCP_TOOL_CATALOG.length})
                  </span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        setGrpDraft({
                          ...grpDraft,
                          allowedActions: MCP_TOOL_CATALOG.filter(
                            (a) => a.risk === 'read'
                          ).map((a) => a.id),
                        })
                      }
                    >
                      Read-only preset
                    </button>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() =>
                        setGrpDraft({
                          ...grpDraft,
                          allowedActions: MCP_TOOL_CATALOG.map((a) => a.id),
                        })
                      }
                    >
                      All
                    </button>
                  </div>
                </div>
                <div className="chk-list">
                  {MCP_TOOL_CATALOG.map((act) => {
                    const on = grpDraft.allowedActions.includes(act.id);
                    return (
                      <div className="chk-row" key={act.id}>
                        <div>
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 6,
                            }}
                          >
                            <span
                              className="mono"
                              style={{ fontWeight: 500 }}
                            >
                              {act.label}
                            </span>
                            <span
                              className={`tag ${
                                act.risk === 'destructive'
                                  ? 'err'
                                  : act.risk === 'write'
                                    ? 'warn'
                                    : ''
                              }`}
                            >
                              {act.risk}
                            </span>
                          </div>
                          <div
                            style={{ fontSize: 11, color: 'var(--t3)' }}
                          >
                            {act.description}
                          </div>
                        </div>
                        <button
                          type="button"
                          className={`sw ${on ? 'on' : ''}`}
                          onClick={() => {
                            const has = grpDraft.allowedActions.includes(
                              act.id
                            );
                            const next = has
                              ? grpDraft.allowedActions.filter(
                                  (x) => x !== act.id
                                )
                              : [...grpDraft.allowedActions, act.id];
                            setGrpDraft({
                              ...grpDraft,
                              allowedActions: next,
                            });
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    Object &amp; field access (
                    {grpDraft.objectPermissions.length} objects)
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--t3)' }}>
                    Click R·C·U·D or expand fields
                  </span>
                </div>
                <div className="chk-list" style={{ maxHeight: 340 }}>
                  {objects.map((o) => {
                    const perm = grpDraft.objectPermissions.find(
                      (p) => p.objectName === o.objectName
                    );
                    const hasAny = Boolean(
                      perm &&
                        (perm.canRead ||
                          perm.canCreate ||
                          perm.canUpdate ||
                          perm.canDelete)
                    );
                    const isExp = expandedObj === o.objectName;
                    const enabledObjFields = o.fields.filter(
                      (f: SalesforceObjectField) => f.enabled
                    );
                    const allowedSet = new Set(perm?.allowedFields || []);
                    const hiddenCount = hasAny
                      ? enabledObjFields.filter(
                          (f: SalesforceObjectField) =>
                            !allowedSet.has(f.fieldName)
                        ).length
                      : 0;

                    return (
                      <div
                        key={o.objectName}
                        style={{ borderBottom: '1px solid var(--bd)' }}
                      >
                        <div
                          className="chk-row"
                          style={{ borderBottom: 'none' }}
                        >
                          <div
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 6,
                              minWidth: 0,
                              flexWrap: 'wrap',
                            }}
                          >
                            <button
                              type="button"
                              className="btn gh sm"
                              style={{ padding: '2px 5px' }}
                              disabled={!hasAny}
                              title="Configure per-field visibility for this group"
                              onClick={() =>
                                setExpandedObj(isExp ? null : o.objectName)
                              }
                            >
                              {isExp ? '▾' : '▸'}
                            </button>
                            <span
                              className="mono"
                              style={{
                                fontWeight: 500,
                                opacity: o.enabled ? 1 : 0.45,
                              }}
                            >
                              {o.objectName}
                            </span>
                            {!o.enabled && (
                              <span className="tag">disabled</span>
                            )}
                            {hasAny && hiddenCount > 0 && (
                              <span className="tag warn">
                                {hiddenCount} hidden
                              </span>
                            )}
                          </div>
                          <span className="crud">
                            {(
                              [
                                ['canRead', 'R'],
                                ['canCreate', 'C'],
                                ['canUpdate', 'U'],
                                ['canDelete', 'D'],
                              ] as const
                            ).map(([k, lbl]) => (
                              <span
                                key={k}
                                className={`cell clk ${
                                  perm?.[k] ? 'on' : ''
                                } ${lbl === 'D' ? 'dng' : ''}`}
                                onClick={() =>
                                  toggleGroupObjectCrud(o.objectName, k)
                                }
                              >
                                {lbl}
                              </span>
                            ))}
                          </span>
                        </div>

                        {isExp && hasAny && (
                          <div
                            style={{
                              padding: '6px 12px 10px 30px',
                              background: 'rgba(0,0,0,0.2)',
                              borderTop: '1px solid var(--bd)',
                            }}
                          >
                            <div
                              style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                alignItems: 'center',
                                fontSize: 11,
                                color: 'var(--t3)',
                                marginBottom: 6,
                              }}
                            >
                              <span>
                                Allowed fields for <b>{grpDraft.name}</b> on{' '}
                                <span className="mono">{o.objectName}</span>
                              </span>
                              <div style={{ display: 'flex', gap: 6 }}>
                                <button
                                  type="button"
                                  className="btn sm"
                                  onClick={() =>
                                    setAllGroupObjectFields(o.objectName, true)
                                  }
                                >
                                  All
                                </button>
                                <button
                                  type="button"
                                  className="btn sm"
                                  onClick={() =>
                                    setAllGroupObjectFields(o.objectName, false)
                                  }
                                >
                                  None
                                </button>
                              </div>
                            </div>
                            <div
                              style={{
                                display: 'flex',
                                flexDirection: 'column',
                                gap: 4,
                              }}
                            >
                              {enabledObjFields.map(
                                (f: SalesforceObjectField) => {
                                  const vis = allowedSet.has(f.fieldName);
                                  const sens = isSensitiveField(
                                    f.fieldName,
                                    f.label
                                  );
                                  return (
                                    <div
                                      key={f.fieldName}
                                      style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center',
                                        fontSize: 11.5,
                                      }}
                                    >
                                      <span>
                                        <span className="mono">
                                          {f.fieldName}
                                        </span>{' '}
                                        <span style={{ color: 'var(--t3)' }}>
                                          · {f.fieldType}
                                        </span>{' '}
                                        {sens && (
                                          <span className="tag warn">
                                            sensitive
                                          </span>
                                        )}
                                      </span>
                                      <button
                                        type="button"
                                        className={`sw ${vis ? 'on' : ''}`}
                                        onClick={() =>
                                          toggleGroupObjectField(
                                            o.objectName,
                                            f.fieldName
                                          )
                                        }
                                      />
                                    </div>
                                  );
                                }
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {liveGroup && (
                <div className="sec">
                  <div className="sec-h">
                    <span className="sec-t">
                      Assigned profiles (
                      {
                        profiles.filter((p) =>
                          getProfileGroupIds(p.id).includes(liveGroup.id)
                        ).length
                      }
                      )
                    </span>
                  </div>
                  <div className="chk-list" style={{ maxHeight: 220 }}>
                    {profiles.map((p) => {
                      const on = getProfileGroupIds(p.id).includes(
                        liveGroup.id
                      );
                      return (
                        <div className="chk-row" key={p.id}>
                          <div>
                            <div style={{ fontWeight: 500 }}>{p.name}</div>
                            <div
                              className="mono"
                              style={{ color: 'var(--t3)' }}
                            >
                              {p.id}
                            </div>
                          </div>
                          <button
                            type="button"
                            className={`sw ${on ? 'on' : ''}`}
                            onClick={() =>
                              onToggleProfileGroup(p.id, liveGroup.id)
                            }
                          />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </>
          )}

          {/* 7. TRAFFIC EVENT DRAWER */}
          {flyout.type === 'traffic' && flyout.data && (
            <>
              <div className="sec">
                <dl className="kv">
                  <dt>Timestamp</dt>
                  <dd className="mono">{flyout.data.timestamp}</dd>
                  <dt>User</dt>
                  <dd>{flyout.data.sfUsername}</dd>
                  <dt>Salesforce profile</dt>
                  <dd>
                    {flyout.data.profileName}{' '}
                    <span className="mono" style={{ color: 'var(--t3)' }}>
                      ({flyout.data.profileId})
                    </span>
                  </dd>
                  <dt>Matched groups</dt>
                  <dd>
                    {flyout.data.matchedGroups &&
                    flyout.data.matchedGroups.length > 0 ? (
                      <div
                        style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}
                      >
                        {flyout.data.matchedGroups.map((gn: string) => (
                          <span key={gn} className="tag acc">
                            {gn}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="tag warn">None</span>
                    )}
                  </dd>
                  <dt>MCP tool</dt>
                  <dd className="mono">{flyout.data.toolName}</dd>
                  <dt>Target object</dt>
                  <dd className="mono">{flyout.data.targetObject}</dd>
                  <dt>Latency</dt>
                  <dd className="mono">{flyout.data.latencyMs} ms</dd>
                  <dt>Result</dt>
                  <dd>
                    <span
                      className={`tag ${
                        flyout.data.status === 'ALLOWED'
                          ? 'ok'
                          : flyout.data.status === 'DENIED'
                            ? 'warn'
                            : 'err'
                      }`}
                    >
                      {flyout.data.status}
                    </span>
                  </dd>
                </dl>
              </div>
              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">
                    Request payload (PII-sanitized)
                  </span>
                  <span className="tag ok">Sensitive values redacted</span>
                </div>
                <pre className="code">
                  {flyout.data.sanitizedRequestPayload ||
                    flyout.data.sanitizedRequest}
                </pre>
              </div>
              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">Response summary</span>
                </div>
                <pre className="code">
                  {flyout.data.sanitizedResponseSummary ||
                    flyout.data.sanitizedResponse}
                </pre>
              </div>
            </>
          )}

          {/* 8. AUDIT EVENT DRAWER */}
          {flyout.type === 'audit' && flyout.data && (
            <>
              <div className="sec">
                <dl className="kv">
                  <dt>Timestamp</dt>
                  <dd className="mono">{flyout.data.timestamp}</dd>
                  <dt>Administrator</dt>
                  <dd>{flyout.data.adminUsername}</dd>
                  <dt>Sign-in method</dt>
                  <dd>
                    <span
                      className={`tag ${
                        String(flyout.data.authMethod).toLowerCase() ===
                        'okta_sso'
                          ? 'acc'
                          : ''
                      }`}
                    >
                      {String(flyout.data.authMethod).toLowerCase() ===
                      'okta_sso'
                        ? 'Okta SSO'
                        : 'Password'}
                    </span>
                  </dd>
                  <dt>Action</dt>
                  <dd className="mono">{flyout.data.action}</dd>
                  <dt>Target</dt>
                  <dd className="mono">{flyout.data.target}</dd>
                  <dt>Source IP</dt>
                  <dd className="mono">{flyout.data.ipAddress}</dd>
                  <dt>Result</dt>
                  <dd>
                    <span className={`tag ${portalAuditResult(String(flyout.data.action)).tone}`}>
                      {portalAuditResult(String(flyout.data.action)).label}
                    </span>
                  </dd>
                </dl>
              </div>
              <div className="sec">
                <div className="sec-h">
                  <span className="sec-t">Change summary</span>
                </div>
                <pre className="code">{flyout.data.details}</pre>
              </div>
            </>
          )}

          {/* 9. LIVE MCP POLICY SIMULATOR */}
          {flyout.type === 'simulator' && (
            <>
              <div className="sec">
                <div className="fld">
                  <label>Caller Salesforce Profile</label>
                  <select
                    className="inp"
                    value={simProfileId}
                    onChange={(e) => setSimProfileId(e.target.value)}
                  >
                    {profiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.id})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="fld">
                  <label>Simulated Copilot User</label>
                  <input
                    className="inp"
                    value={simUsername}
                    onChange={(e) => setSimUsername(e.target.value)}
                    placeholder="Jordan Lee"
                  />
                </div>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: 10,
                  }}
                >
                  <div className="fld">
                    <label>MCP Tool</label>
                    <select
                      className="inp mono"
                      value={simTool}
                      onChange={(e) =>
                        setSimTool(e.target.value as McpActionType)
                      }
                    >
                      {MCP_TOOL_CATALOG.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.label} ({t.risk})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="fld">
                    <label>Target SObject</label>
                    <select
                      className="inp mono"
                      value={simObject}
                      onChange={(e) => setSimObject(e.target.value)}
                    >
                      {objects.map((o) => (
                        <option key={o.objectName} value={o.objectName}>
                          {o.objectName} {!o.enabled ? '(Disabled)' : ''}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                  <button
                    type="button"
                    className="btn pri"
                    disabled={busy}
                    onClick={async () => {
                      setBusy(true);
                      try {
                        const res = await onTestMcpCall({
                          profileId: simProfileId,
                          toolName: simTool,
                          targetObject: simObject,
                          username: simUsername,
                        });
                        setSimResult(res);
                        await onRefreshWorkspace();
                      } catch {
                        // The error toast is already showing; stay here so the admin can retry.
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    Run MCP Policy Check
                  </button>
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={handleRunBurst}
                  >
                    Run 6-Event Traffic Burst
                  </button>
                </div>
              </div>

              {simResult?.evaluation && (
                <div className="sec">
                  <div className="sec-h">
                    <span className="sec-t">Policy Evaluation Result</span>
                    <span
                      className={`tag ${
                        simResult.evaluation.permitted ? 'ok' : 'err'
                      }`}
                    >
                      {simResult.evaluation.permitted
                        ? 'ALLOWED'
                        : 'DENIED BY POLICY'}
                    </span>
                  </div>
                  <dl className="kv" style={{ marginBottom: 10 }}>
                    <dt>Decision reason</dt>
                    <dd>{simResult.evaluation.reason}</dd>
                    <dt>Matched groups</dt>
                    <dd>
                      {(simResult.evaluation.matchedGroups || []).length > 0
                        ? simResult.evaluation.matchedGroups.join(', ')
                        : 'None'}
                    </dd>
                    <dt>Allowed fields</dt>
                    <dd className="mono">
                      {(simResult.evaluation.allowedFields || []).length > 0
                        ? `${simResult.evaluation.allowedFields.length} fields (${simResult.evaluation.allowedFields.slice(0, 6).join(', ')}${simResult.evaluation.allowedFields.length > 6 ? '…' : ''})`
                        : '0 fields'}
                    </dd>
                  </dl>
                  {simResult.simulatorBearerToken && (
                    <div>
                      <div
                        style={{
                          fontSize: 11,
                          color: 'var(--t3)',
                          marginBottom: 4,
                        }}
                      >
                        Signed Simulator Bearer Token (for{' '}
                        <span className="mono">POST /api/mcp</span>):
                      </div>
                      <pre className="code">
                        {simResult.simulatorBearerToken}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* FOOTER */}
        <div className="fly-f">
          <div>
            {flyout.type === 'profile' && liveProfile && (
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  type="button"
                  className="btn dng"
                  disabled={busy}
                  onClick={async () => {
                    if (!confirmDelete) {
                      setConfirmDelete(true);
                      return;
                    }
                    setBusy(true);
                    try {
                      await onDeleteProfile(liveProfile.id);
                      onClose();
                    } catch {
                      // The error toast is already showing; stay here so the admin can retry.
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  {confirmDelete
                    ? 'Click again to remove profile'
                    : 'Delete profile'}
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() =>
                    onOpenFlyout({
                      type: 'simulator',
                      data: { profileId: liveProfile.id },
                    })
                  }
                >
                  Test MCP Call
                </button>
              </div>
            )}

            {flyout.type === 'group' && liveGroup && (
              <button
                type="button"
                className="btn dng"
                disabled={busy}
                onClick={async () => {
                  if (!confirmDelete) {
                    setConfirmDelete(true);
                    return;
                  }
                  setBusy(true);
                  try {
                    await onDeleteGroup(liveGroup.id);
                    onClose();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {confirmDelete
                  ? 'Click again to delete group'
                  : 'Delete group'}
              </button>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            {flyout.type === 'newprofile' && (
              <button
                type="button"
                className="btn pri"
                disabled={busy || !newProfId.trim() || !newProfName.trim()}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onUpsertProfile(
                      newProfId.trim(),
                      newProfName.trim()
                    );
                    onClose();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Create profile
              </button>
            )}

            {flyout.type === 'import' && (
              <button
                type="button"
                className="btn pri"
                disabled={busy || validCsvRows.length === 0}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onImportCsv(csvText);
                    onClose();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Import {validCsvRows.length} profiles
              </button>
            )}

            {flyout.type === 'sync' && pendingUploadFiles.length > 0 && (
              <button
                type="button"
                className="btn pri"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onSyncUploadedFiles(pendingUploadFiles);
                    onClose();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Apply sync ({uploadPreview.length} objects)
              </button>
            )}

            {flyout.type === 'group' && grpDraft && (
              <button
                type="button"
                className="btn pri"
                disabled={busy || !grpDraft.name.trim()}
                onClick={async () => {
                  setBusy(true);
                  try {
                    await onSaveGroup(grpDraft);
                    onClose();
                  } catch {
                    // The error toast is already showing; stay here so the admin can retry.
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Save group
              </button>
            )}

            {flyout.type === 'traffic' && flyout.data && (
              <>
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    onNavigateView('traffic', flyout.data.sfUsername);
                    onClose();
                  }}
                >
                  Filter by this user
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    const prof = profiles.find(
                      (p) => p.id === flyout.data.profileId
                    );
                    if (prof) onOpenFlyout({ type: 'profile', data: prof });
                  }}
                >
                  Open profile
                </button>
              </>
            )}

            <button type="button" className="btn" onClick={onClose}>
              Close
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
