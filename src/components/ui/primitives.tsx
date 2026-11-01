import React from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { McpActionType } from '@/types/governance';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const MCP_TOOL_CATALOG: Array<{
  id: McpActionType;
  label: string;
  risk: 'read' | 'write' | 'destructive';
  description: string;
}> = [
  {
    id: 'list_enabled_objects',
    label: 'list_enabled_objects',
    risk: 'read',
    description: 'Lists Salesforce SObjects permitted for this caller via Profile Groups.',
  },
  {
    id: 'describe_object',
    label: 'describe_object',
    risk: 'read',
    description: 'Returns allowed fields and metadata for an enabled Salesforce SObject.',
  },
  {
    id: 'soql_query',
    label: 'soql_query',
    risk: 'read',
    description: 'Executes a read-only SOQL SELECT restricted to permitted objects & fields.',
  },
  {
    id: 'get_record',
    label: 'get_record',
    risk: 'read',
    description: 'Fetches a single Salesforce record by ID filtered to allowed fields.',
  },
  {
    id: 'create_record',
    label: 'create_record',
    risk: 'write',
    description: 'Creates a new record on an object where group grants Create (C) access.',
  },
  {
    id: 'update_record',
    label: 'update_record',
    risk: 'write',
    description: 'Updates permitted fields on an existing record where group grants Update (U).',
  },
  {
    id: 'delete_record',
    label: 'delete_record',
    risk: 'destructive',
    description: 'Deletes a record by ID (requires explicit Delete (D) permission).',
  },
];

export function isSensitiveField(fieldName: string, label?: string): boolean {
  const target = `${fieldName} ${label || ''}`;
  return /ssn|tax|birth|salary|password|secret|margin|payment|routing|credit|bank/i.test(
    target
  );
}

export function formatShortTime(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatDateShort(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
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

export function Switch({
  checked,
  onCheckedChange,
  disabled,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onCheckedChange(!checked);
      }}
      className={cn(
        'sw',
        checked && 'on',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    />
  );
}

export function Input({
  className,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn('inp', className)} {...props} />;
}
