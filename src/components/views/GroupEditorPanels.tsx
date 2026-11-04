'use client';

import React, { useEffect, useRef, useState } from 'react';
import type {
  AccessGroupChangeSource,
  AccessGroupHistoryEntry,
  SalesforceObject,
} from '@/types/governance';
import type { GroupAvailabilityIssue } from '@/groups/groupGrants';
import { accessGroupToXml } from '@/groups/groupXml';
import { downloadTextFile, groupXmlFileName } from './accessGroupDraft';

/** Larger files are not an Access Group: a group with every field of every object is far smaller. */
export const MAX_GROUP_XML_BYTES = 512 * 1024;

/** Reads a file the admin picked, refusing one too large to be a group file. */
export async function readGroupXmlFile(file: File): Promise<string> {
  if (file.size > MAX_GROUP_XML_BYTES) {
    throw new Error(`${file.name} is ${Math.round(file.size / 1024)} KB; an Access Group file is at most 512 KB.`);
  }
  return file.text();
}

export function formatWhen(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso || '—';
  return d.toLocaleString([], {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const ISSUE_KIND_LABEL: Record<GroupAvailabilityIssue['kind'], string> = {
  action: 'MCP action',
  object: 'Object',
  field: 'Field',
};

/** Everything in a group that is not available, or broken, with the reason for each. */
export function GroupIssueList({ issues, max = 6 }: { issues: GroupAvailabilityIssue[]; max?: number }) {
  const [showAll, setShowAll] = useState(false);
  if (issues.length === 0) return null;
  const unavailable = issues.filter((i) => i.status === 'unavailable').length;
  const broken = issues.length - unavailable;
  const shown = showAll ? issues : issues.slice(0, max);
  return (
    <div className={`notice ${broken > 0 ? 'err' : 'warn'}`} role="status">
      <div className="notice-t">
        {[unavailable > 0 ? `${unavailable} not available` : '', broken > 0 ? `${broken} broken` : '']
          .filter(Boolean)
          .join(' · ')}
        <span className="notice-s">
          {' '}
          — kept on the group so you can review why. Not available grants nothing; broken is granted but
          fails in Salesforce.
        </span>
      </div>
      <ul className="notice-l">
        {shown.map((issue) => (
          <li key={`${issue.kind}:${issue.objectName}:${issue.name}`}>
            <span className={`tag ${issue.status === 'broken' ? 'err' : 'warn'}`}>
              {issue.status === 'broken' ? 'broken' : 'not available'}
            </span>
            <span className="notice-k">{ISSUE_KIND_LABEL[issue.kind]}</span>
            <span className="mono">
              {issue.kind === 'field' ? `${issue.objectName}.${issue.name}` : issue.name}
            </span>
            <span className="notice-m">{issue.message}</span>
          </li>
        ))}
      </ul>
      {issues.length > max && (
        <button type="button" className="btn gh sm" onClick={() => setShowAll(!showAll)}>
          {showAll ? 'Show fewer' : `Show all ${issues.length}`}
        </button>
      )}
    </div>
  );
}

/** The character offset where a 1-based line starts. */
function offsetOfLine(text: string, line: number): number {
  let offset = 0;
  for (let n = 1; n < line; n++) {
    const next = text.indexOf('\n', offset);
    if (next === -1) return text.length;
    offset = next + 1;
  }
  return offset;
}

interface GroupXmlPanelProps {
  xmlText: string;
  onChangeText: (text: string) => void;
  error: { message: string; line?: number } | null;
  /** Something to know about the file that is not an error. */
  notice: string | null;
  onLoadFile: (fileName: string, text: string) => void;
  onLoadFileError: (message: string) => void;
  onDiscard: () => void;
  onReformat: () => void;
}

/**
 * The group as editable XML. Every valid edit updates the draft at once, so the Visual view and Save
 * always show what the XML says; while the XML has an error, the last valid version stays in the draft.
 */
export function GroupXmlPanel({
  xmlText,
  onChangeText,
  error,
  notice,
  onLoadFile,
  onLoadFileError,
  onDiscard,
  onReformat,
}: GroupXmlPanelProps) {
  const textRef = useRef<HTMLTextAreaElement | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);

  const goToLine = (line: number) => {
    const area = textRef.current;
    if (!area) return;
    const start = offsetOfLine(xmlText, line);
    const end = xmlText.indexOf('\n', start);
    area.focus();
    area.setSelectionRange(start, end === -1 ? xmlText.length : end);
  };

  return (
    <div className="sec">
      <div className="sec-h">
        <span className="sec-t">Group XML</span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button type="button" className="btn sm" onClick={() => fileRef.current?.click()}>
            Load file…
          </button>
          <button
            type="button"
            className="btn sm"
            disabled={Boolean(error)}
            title="Rewrites the XML from the group, with a note on each item that is not available"
            onClick={onReformat}
          >
            Reformat
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".xml,application/xml,text/xml"
            style={{ display: 'none' }}
            onChange={async (e) => {
              const file = e.target.files?.[0];
              e.target.value = '';
              if (!file) return;
              try {
                onLoadFile(file.name, await readGroupXmlFile(file));
              } catch (err: any) {
                onLoadFileError(err?.message || 'The file could not be read.');
              }
            }}
          />
        </div>
      </div>
      <textarea
        ref={textRef}
        className={`inp xml-ed ${error ? 'bad' : ''}`}
        spellCheck={false}
        aria-label="Access group XML"
        aria-invalid={Boolean(error)}
        value={xmlText}
        onChange={(e) => onChangeText(e.target.value)}
      />
      {error ? (
        <div className="notice err" role="alert">
          <div className="notice-t">
            {error.line ? `Line ${error.line}: ` : ''}
            {error.message}
          </div>
          <div className="notice-s">
            The switches and Save still hold the last valid XML. Fix the error, or discard your XML edits.
          </div>
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            {error.line && (
              <button type="button" className="btn sm" onClick={() => goToLine(error.line!)}>
                Go to line {error.line}
              </button>
            )}
            <button type="button" className="btn sm" onClick={onDiscard}>
              Discard XML edits
            </button>
          </div>
        </div>
      ) : (
        <div className="xml-hint">
          Edits apply as you type and show in the Visual view. Comments are notes from this server and are
          not kept.
          {notice && <div style={{ marginTop: 4 }}>{notice}</div>}
        </div>
      )}
    </div>
  );
}

const KIND_TAG: Record<AccessGroupHistoryEntry['kind'], { label: string; cls: string }> = {
  created: { label: 'Created', cls: 'ok' },
  updated: { label: 'Edited', cls: 'acc' },
  deleted: { label: 'Deleted', cls: 'err' },
  catalog: { label: 'Objects change', cls: 'warn' },
};

export const CHANGE_SOURCE_LABEL: Record<AccessGroupChangeSource, string> = {
  editor: 'Visual editor',
  xml_editor: 'XML editor',
  xml_import: 'XML import',
  version_restore: 'Restored version',
  objects: 'Salesforce > Objects',
  org_sync: 'Org sync',
  sample_data: 'Sample data',
};

interface GroupHistoryPanelProps {
  groupId: string;
  loadHistory: (groupId: string) => Promise<AccessGroupHistoryEntry[]>;
  objects: SalesforceObject[];
  onLoadVersion: (entry: AccessGroupHistoryEntry) => void;
}

/** Who changed the group, when, how and what changed, newest first, with each version as XML. */
export function GroupHistoryPanel({ groupId, loadHistory, objects, onLoadVersion }: GroupHistoryPanelProps) {
  const [entries, setEntries] = useState<AccessGroupHistoryEntry[] | null>(null);
  const [error, setError] = useState('');
  const [openId, setOpenId] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setEntries(null);
    setError('');
    loadHistory(groupId).then(
      (rows) => live && setEntries(rows),
      (err) => live && setError(err?.message || 'The history could not be loaded.')
    );
    return () => {
      live = false;
    };
  }, [groupId, loadHistory]);

  if (error) return <div className="notice err">{error}</div>;
  if (!entries) return <div className="empty">Loading history…</div>;
  if (entries.length === 0) {
    return (
      <div className="empty">
        No recorded changes yet. Groups saved before history was added start their history with their next
        change.
      </div>
    );
  }

  return (
    <div className="sec">
      <div className="sec-h">
        <span className="sec-t">History ({entries.length})</span>
        <span style={{ fontSize: 11, color: 'var(--t3)' }}>Newest first</span>
      </div>
      <div className="hist">
        {entries.map((entry, index) => {
          const kind = KIND_TAG[entry.kind] || KIND_TAG.updated;
          const isOpen = openId === entry.id;
          const xml = isOpen ? accessGroupToXml(entry.snapshot, { objects }) : '';
          return (
            <div className="hist-it" key={entry.id}>
              <div className="hist-h">
                <span className={`tag ${kind.cls}`}>{kind.label}</span>
                <span className="tag">{CHANGE_SOURCE_LABEL[entry.source] || entry.source}</span>
                {index === 0 && entry.kind !== 'deleted' && <span className="tag acc">current</span>}
                <span className="hist-when mono" title={entry.timestamp}>
                  {formatWhen(entry.timestamp)}
                </span>
              </div>
              <div className="hist-who">
                {entry.adminUsername}
                {entry.authMethod === 'okta_sso' ? ' · Okta SSO' : entry.authMethod === 'password' ? ' · password' : ''}
                {entry.sourceDetail && <span className="mono"> · {entry.sourceDetail}</span>}
              </div>
              <ul className="hist-c">
                {entry.changes.map((line, i) => (
                  <li key={i}>{line}</li>
                ))}
              </ul>
              <div className="hist-a">
                <button type="button" className="btn gh sm" onClick={() => setOpenId(isOpen ? null : entry.id)}>
                  {isOpen ? 'Hide XML' : 'View XML'}
                </button>
                <button
                  type="button"
                  className="btn gh sm"
                  onClick={() =>
                    downloadTextFile(
                      accessGroupToXml(entry.snapshot, { objects }),
                      groupXmlFileName(`${entry.snapshot.name}-${entry.timestamp.slice(0, 19).replace(/[:T]/g, '-')}`)
                    )
                  }
                >
                  Download
                </button>
                {index > 0 && (
                  <button
                    type="button"
                    className="btn gh sm"
                    title="Puts this version in the editor. Nothing changes until you save."
                    onClick={() => onLoadVersion(entry)}
                  >
                    Load this version
                  </button>
                )}
              </div>
              {isOpen && <pre className="code hist-x">{xml}</pre>}
            </div>
          );
        })}
      </div>
    </div>
  );
}
