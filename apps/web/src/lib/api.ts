// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Types mirror contracts/openapi/secretmesh.yaml.

export type Role = "org_admin" | "member";
export type Scope =
  | "org:read"
  | "org:write"
  | "members:read"
  | "members:write"
  | "secrets:read"
  | "secrets:write"
  | "audit:read";
export const SCOPES: Scope[] = [
  "org:read",
  "org:write",
  "members:read",
  "members:write",
  "secrets:read",
  "secrets:write",
  "audit:read",
];

export interface OrganizationMembership {
  id: string;
  name: string;
  slug: string;
  role: Role;
  require_mfa: boolean;
}

export interface Me {
  user: { id: string; email: string; display_name: string };
  session: { mfa: boolean; authenticated_at?: string };
  organizations: OrganizationMembership[];
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  require_mfa: boolean;
  role: Role;
}

export interface Member {
  user_id: string;
  email: string;
  display_name: string;
  role: Role;
  joined_at: string;
}

export interface Invitation {
  id: string;
  email: string;
  role: Role;
  invited_by?: string;
  created_at: string;
  expires_at: string;
}

export interface ApiToken {
  id: string;
  name: string;
  display_prefix: string;
  scopes: Scope[];
  created_by: string;
  created_at: string;
  expires_at: string;
  last_used_at?: string;
}

export type EnvironmentKind = "development" | "staging" | "production";
export type Classification = "internal" | "confidential" | "restricted";
export const CLASSIFICATIONS: Classification[] = ["internal", "confidential", "restricted"];
export type BindingRole =
  | "cloud_admin"
  | "security_admin"
  | "secret_admin"
  | "developer"
  | "approver"
  | "auditor"
  | "break_glass";
export const BINDING_ROLES: BindingRole[] = [
  "cloud_admin",
  "security_admin",
  "secret_admin",
  "developer",
  "approver",
  "auditor",
  "break_glass",
];
export type Operation = "create" | "update" | "delete";
export type ChangeStatus =
  | "pending"
  | "approved"
  | "executing"
  | "succeeded"
  | "failed"
  | "rejected"
  | "cancelled"
  | "expired";
export const CHANGE_STATUSES: ChangeStatus[] = [
  "pending",
  "approved",
  "executing",
  "succeeded",
  "failed",
  "rejected",
  "cancelled",
  "expired",
];

export interface Environment {
  id: string;
  name: string;
  kind: EnvironmentKind;
  created_at: string;
}

export interface Capabilities {
  secret_create: boolean;
  secret_update: boolean;
  secret_delete: boolean;
  secret_reveal: boolean;
  discovery: boolean;
  versioning: boolean;
  native_rotation: boolean;
  update_staging: string;
  create_staging: string;
}

export interface Connection {
  id: string;
  name: string;
  provider: string;
  status: string;
  config: Record<string, string>;
  default_environment_id?: string;
  last_synced_at?: string;
  last_sync_error?: string;
  capabilities?: Capabilities;
  created_at: string;
}

export interface SyncResult {
  rotated: number;
  imported: number;
  updated: number;
  removed: number;
  unassigned: number;
}

export interface RoleBinding {
  id: string;
  user_id: string;
  email: string;
  role: BindingRole;
  environment_id?: string;
  created_at: string;
}

export interface Secret {
  id: string;
  name: string;
  connection_id: string;
  environment_id: string;
  environment_kind: EnvironmentKind;
  classification: Classification;
  provider_ref: string;
  status: string;
  current_version?: string;
  origin?: "created" | "discovered";
  description?: string;
  tags?: Record<string, string>;
  provider_metadata?: Record<string, string>;
  last_seen_at?: string;
  owner_user_id?: string;
  last_rotated_at?: string;
  rotation_strategy?: RotationStrategy;
  rotation_enabled?: boolean;
  next_rotation_at?: string;
  created_at: string;
  updated_at: string;
}

export type RotationStrategy = "native" | "manual";

export interface RotationPolicy {
  secret_id: string;
  strategy: RotationStrategy;
  interval_days: number;
  reminder_days: number[];
  escalation_days: number[];
  enabled: boolean;
  next_rotation_at: string;
  updated_by?: string;
  updated_at: string;
}

export interface RotationExecution {
  id: string;
  secret_id: string;
  trigger: "schedule" | "manual";
  requested_by?: string;
  status: "scheduled" | "rotating" | "verifying" | "succeeded" | "failed";
  due_at: string;
  provider_version_id?: string;
  cloud_request_id?: string;
  error_code?: string;
  rotate_started_at?: string;
  finished_at?: string;
  created_at: string;
}

export interface NotificationChannel {
  id: string;
  kind: "email" | "slack";
  name: string;
  webhook_secret_id?: string;
  enabled: boolean;
  created_at: string;
}

export interface NotificationDelivery {
  notification_id: string;
  event: string;
  subject: string;
  channel: string;
  status: "pending" | "sent" | "failed";
  attempts: number;
  last_error?: string;
  created_at: string;
  sent_at?: string;
}

export interface SecretVersion {
  id: string;
  stages: string[];
  created_at?: string;
}

export interface Decision {
  approver_id: string;
  decision: "approve" | "reject";
  mfa: boolean;
  comment?: string;
  created_at: string;
}

export interface ChangeRequest {
  id: string;
  operation: Operation;
  status: ChangeStatus;
  secret_id?: string;
  secret_name: string;
  connection_id: string;
  environment_id: string;
  environment_kind: EnvironmentKind;
  classification: Classification;
  required_approvals: number;
  binding_hash: string;
  break_glass?: boolean;
  reason?: string;
  requested_by: string;
  decisions: Decision[];
  failure_code?: string;
  provider_version_id?: string;
  cloud_request_id?: string;
  created_at: string;
  expires_at: string;
  completed_at?: string;
}

export interface AuditEvent {
  id: string;
  seq: number;
  occurred_at: string;
  actor_type: string;
  actor_id?: string;
  action: string;
  resource_type: string;
  resource_id: string;
  decision: string;
  change_request_id?: string;
  details: Record<string, string>;
  hash: string;
}

export interface AuditVerification {
  valid: boolean;
  events_checked: number;
  checkpoints_verified: number;
  head_seq: number;
  last_checkpoint_seq?: number;
  last_exported_seq?: number;
  first_invalid_seq?: number;
  problem?: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/** Calls the SecretMesh API. Throws ApiError for non-2xx responses. */
export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => null)) as {
      error?: { code: string; message: string };
    } | null;
    throw new ApiError(res.status, err?.error?.code ?? "unknown", err?.error?.message ?? `request failed (${res.status})`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

/** Returns the current user, or null when not signed in. */
export async function getMe(): Promise<Me | null> {
  try {
    return await api<Me>("GET", "/me");
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

/** URL that re-authenticates at the identity provider and returns to `returnTo`. */
export function stepUpURL(returnTo: string): string {
  return `/auth/login?step_up=1&return_to=${encodeURIComponent(returnTo)}`;
}
