'use client';

import React from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { AVAILABLE_MCP_ACTIONS } from '@/types/governance';
import type { McpActionId, McpActionType } from '@/types/governance';
import { useModalDialog } from '@/components/views/useModalDialog';
import { statusTone, statusToneClass, type StatusTone } from './statusTone';
import { formatDateUtc, formatLocalTimestamp, formatTimestamp } from './timestamp';
import type { ToastItem } from './toastQueue';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Keyed by McpActionId so the compiler rejects a tool the server does not have, or a missing one.
const MCP_TOOL_DETAILS: Record<
  McpActionId,
  { risk: 'read' | 'write' | 'destructive'; description: string }
> = {
  list_enabled_objects: {
    risk: 'read',
    description: 'Lists Salesforce SObjects permitted for this caller via Profile Groups.',
  },
  describe_object: {
    risk: 'read',
    description: 'Returns allowed fields and metadata for an enabled Salesforce SObject.',
  },
  soql_query: {
    risk: 'read',
    description: 'Executes a read-only SOQL SELECT restricted to permitted objects & fields.',
  },
  get_record: {
    risk: 'read',
    description: 'Fetches a single Salesforce record by ID filtered to allowed fields.',
  },
  create_record: {
    risk: 'write',
    description: 'Creates a new record on an object where group grants Create (C) access.',
  },
  update_record: {
    risk: 'write',
    description: 'Updates permitted fields on an existing record where group grants Update (U).',
  },
  delete_record: {
    risk: 'destructive',
    description: 'Deletes a record by ID (requires explicit Delete (D) permission).',
  },
};

export const MCP_TOOL_CATALOG: Array<{
  id: McpActionType;
  label: string;
  risk: 'read' | 'write' | 'destructive';
  description: string;
}> = AVAILABLE_MCP_ACTIONS.map(({ id }) => ({ id, label: id, ...MCP_TOOL_DETAILS[id] }));

export function isSensitiveField(fieldName: string, label?: string): boolean {
  const target = `${fieldName} ${label || ''}`;
  return /ssn|tax|birth|salary|password|secret|margin|payment|routing|credit|bank/i.test(
    target
  );
}

export function Card({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('card', className)} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('card-h', className)} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3 className={cn('card-t m-0', className)} {...props}>
      {children}
    </h3>
  );
}

export function CardDescription({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p className={cn('card-s m-0 mt-0.5', className)} {...props}>
      {children}
    </p>
  );
}

export function CardContent({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('card-b', className)} {...props}>
      {children}
    </div>
  );
}

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?:
    | 'default'
    | 'indigo'
    | 'emerald'
    | 'amber'
    | 'rose'
    | 'slate'
    | 'violet';
}

export function Badge({
  className,
  variant = 'default',
  children,
  ...props
}: BadgeProps) {
  const variants: Record<NonNullable<BadgeProps['variant']>, string> = {
    default: 'tag',
    slate: 'tag',
    indigo: 'tag acc',
    violet: 'tag pur',
    emerald: 'tag ok',
    amber: 'tag warn',
    rose: 'tag err',
  };

  return (
    <span className={cn(variants[variant], className)} {...props}>
      {children}
    </span>
  );
}

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
}

export function Button({
  className,
  variant = 'primary',
  size = 'md',
  children,
  ...props
}: ButtonProps) {
  const variants = {
    primary: 'btn pri',
    secondary: 'btn',
    outline: 'btn',
    ghost: 'btn gh',
    danger: 'btn dng',
  };

  const sizes = {
    sm: 'sm',
    md: '',
    lg: 'px-4 py-2 text-xs',
  };

  return (
    <button
      className={cn(variants[variant], sizes[size], className)}
      {...props}
    >
      {children}
    </button>
  );
}

/**
 * A switch with an accessible name. `label` is required: an unlabelled role="switch" reads as "switch,
 * off" with nothing to say what it turns on. Pass `labelHidden` to keep the name off screen.
 */
export function Switch({
  checked,
  onCheckedChange,
  disabled,
  label,
  labelHidden = true,
  describedBy,
  className,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  label: string;
  labelHidden?: boolean;
  describedBy?: string;
  className?: string;
}) {
  const button = (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={labelHidden ? label : undefined}
      aria-describedby={describedBy}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onCheckedChange(!checked);
      }}
      className={cn('sw', checked && 'on', disabled && 'opacity-50 cursor-not-allowed', className)}
    />
  );
  if (labelHidden) return button;
  return (
    <label className="sw-row">
      {button}
      <span>{label}</span>
    </label>
  );
}

/** A two-state button (a filter chip, Live/Paused): `aria-pressed` says which state it is in. */
export function ToggleButton({
  pressed,
  onPressedChange,
  className,
  children,
  ...props
}: Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, 'onClick'> & {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      className={cn('tgl', pressed && 'on', className)}
      onClick={() => onPressedChange(!pressed)}
      {...props}
    >
      {children}
    </button>
  );
}

/**
 * A runtime status (ALLOWED, DENIED, ERROR, SUCCESS, FAILED, a connection state) in its one colour,
 * from statusTone(). The dot's shape differs per tone, so it never rests on colour alone.
 */
export function StatusBadge({
  status,
  tone,
  label,
  dot = true,
  className,
  title,
}: {
  status?: string | null;
  /** Overrides the tone read from `status`, for a label that is not itself a status word. */
  tone?: StatusTone;
  label?: React.ReactNode;
  dot?: boolean;
  className?: string;
  title?: string;
}) {
  const resolved = tone ?? statusTone(status);
  const toneClass = statusToneClass(resolved);
  return (
    <span className={cn('tag', toneClass, className)} title={title} data-tone={resolved}>
      {dot && <span className={cn('dot', toneClass || 'off')} aria-hidden="true" />}
      {label ?? status}
    </span>
  );
}

function LockIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 0 1 8 0v3" />
    </svg>
  );
}

/**
 * An identifier as the API knows it: SObject, field, tool, SOQL, Salesforce IDs, usernames, Okta client
 * ID / issuer / group claim, IP addresses, log event ids, sync run ids, certificate fingerprints, the
 * policy revision. Mono, never translated. `locked` marks Tier C (sync-sourced, read-only) values.
 */
export function ApiName({
  children,
  locked = false,
  title,
  className,
}: {
  children: React.ReactNode;
  locked?: boolean;
  title?: string;
  className?: string;
}) {
  return (
    <code
      className={cn('tag mono api-name', locked && 'lock', className)}
      title={title ?? (locked ? 'Comes from Salesforce. Change it in Salesforce, then Sync now.' : undefined)}
    >
      {locked && <LockIcon />}
      {children}
    </code>
  );
}

/** A count, latency or status code: tabular figures, and '—' (never 0) when there is no value yet. */
export function Num({
  value,
  unit,
  fallback = '—',
  className,
  format = (n: number) => n.toLocaleString('en-US'),
}: {
  value: number | null | undefined;
  unit?: string;
  fallback?: string;
  className?: string;
  format?: (n: number) => string;
}) {
  const shown = typeof value === 'number' && Number.isFinite(value) ? format(value) : fallback;
  return (
    <span className={cn('num', className)}>
      {shown}
      {unit && shown !== fallback ? <span className="num-unit"> {unit}</span> : null}
    </span>
  );
}

/** A moment, always with its date and zone (UTC); the admin's local time is in the tooltip. */
export function Timestamp({
  iso,
  precision = 'second',
  className,
}: {
  iso: string | null | undefined;
  precision?: 'second' | 'date';
  className?: string;
}) {
  if (!iso) return <span className={cn('num', className)}>—</span>;
  const text = precision === 'date' ? formatDateUtc(iso) : formatTimestamp(iso);
  return (
    <time className={cn('num', className)} dateTime={iso} title={`${formatTimestamp(iso)} · ${formatLocalTimestamp(iso)}`}>
      {text}
    </time>
  );
}

/**
 * A modal dialog on useModalDialog: focus starts on `initialFocus` (Cancel) or the box, Tab stays in,
 * Escape and a scrim click call `onClose`, Cmd/Ctrl+K cannot reach the page behind. `onClose` is where
 * a caller puts its unsaved-changes guard.
 */
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  role = 'dialog',
  width = 480,
  initialFocus = 'first-button',
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
  /** Renders the actions; the first button gets initial focus unless initialFocus is 'box'. */
  footer?: (modal: { close: () => void; initialFocusRef: React.RefObject<HTMLButtonElement | null> }) => React.ReactNode;
  role?: 'dialog' | 'alertdialog';
  width?: number;
  initialFocus?: 'first-button' | 'box';
}) {
  const modal = useModalDialog(open, onClose);
  const titleId = React.useId();
  const bodyId = React.useId();
  if (!open) return null;
  return (
    <div className="cmdk-scrim modal-scrim" onClick={modal.close}>
      <div
        ref={modal.dialogRef}
        className="cmdk-box"
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? bodyId : undefined}
        tabIndex={-1}
        style={{ maxWidth: width }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-h">
          <div className="card-t" id={titleId}>
            {title}
          </div>
        </div>
        <div className="card-b">
          {description && (
            <p id={bodyId} style={{ fontSize: 12.5, color: 'var(--t2)', marginTop: 0 }}>
              {description}
            </p>
          )}
          {children}
          {footer && (
            <div className="dlg-actions">
              {footer({
                close: modal.close,
                initialFocusRef: initialFocus === 'box' ? { current: null } : modal.initialFocusRef,
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * The slide-over drawer, a modal on useModalDialog like Dialog: Escape, the scrim and ✕ all call
 * `onClose` (the caller's unsaved-changes guard), focus starts on ✕ and returns to the opener.
 */
export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  label = 'Details drawer',
}: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  label?: string;
}) {
  const modal = useModalDialog<HTMLElement, HTMLButtonElement>(open, onClose);
  const titleId = React.useId();
  if (!open) return null;
  return (
    <>
      <div className="scrim" onClick={modal.close} />
      <aside
        ref={modal.dialogRef}
        className="fly"
        role="dialog"
        aria-modal="true"
        aria-label={label}
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="fly-h">
          <div>
            <div className="fly-t" id={titleId}>
              {title}
            </div>
            {subtitle && <div className="fly-s">{subtitle}</div>}
          </div>
          <button
            ref={modal.initialFocusRef}
            type="button"
            className="btn gh sm"
            onClick={modal.close}
            title="Close (Esc)"
            aria-label="Close drawer"
          >
            ✕
          </button>
        </div>
        <div className="fly-b">{children}</div>
        {footer}
      </aside>
    </>
  );
}

/**
 * The stacked toast region, above every drawer and modal (--z-toast). Errors are role="alert" and stay
 * until dismissed or replaced; others are polite. A toast with `undo` shows an Undo button.
 */
export function ToastRegion({
  toasts,
  onDismiss,
}: {
  toasts: readonly ToastItem[];
  onDismiss: (id: number) => void;
}) {
  return (
    <div className="toast-region" aria-label="Notifications">
      <div role="status" aria-live="polite" className="toast-stack">
        {toasts.filter((t) => t.kind !== 'error').map((t) => (
          <Toast key={t.id} toast={t} onDismiss={onDismiss} />
        ))}
      </div>
      <div role="alert" aria-live="assertive" className="toast-stack">
        {toasts.filter((t) => t.kind === 'error').map((t) => (
          <Toast key={t.id} toast={t} onDismiss={onDismiss} />
        ))}
      </div>
    </div>
  );
}

function Toast({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: number) => void }) {
  return (
    <div className={cn('toast-banner', toast.kind === 'error' && 'is-error')} data-kind={toast.kind}>
      <span className={cn('dot', toast.kind === 'error' ? 'st-error' : 'st-allowed')} aria-hidden="true" />
      <span className="toast-msg">{toast.message}</span>
      {toast.undo && (
        <button
          type="button"
          className="btn sm"
          onClick={() => {
            onDismiss(toast.id);
            toast.undo?.run();
          }}
        >
          {toast.undo.label || 'Undo'}
        </button>
      )}
      <button type="button" className="btn gh sm" aria-label="Dismiss notification" onClick={() => onDismiss(toast.id)}>
        ✕
      </button>
    </div>
  );
}

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn('inp', className)} {...props} />;
}
