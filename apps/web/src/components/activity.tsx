// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import {
  Activity,
  Bell,
  CheckCircle2,
  Cloud,
  Eye,
  GitPullRequestArrow,
  KeyRound,
  RefreshCw,
  Siren,
  UserPlus,
  Users,
  XCircle,
} from "lucide-react";
import type { AuditEvent } from "@/lib/api";
import { ago } from "@/components/ui";

type Tone = "" | "success" | "danger" | "brand" | "warning";

const known: Record<string, [string, Tone, ReactNode]> = {
  "change_request.submitted": ["submitted a change", "brand", <GitPullRequestArrow key="i" size={15} />],
  "change_request.approved": ["change approved", "success", <CheckCircle2 key="i" size={15} />],
  "change_request.rejected": ["change rejected", "danger", <XCircle key="i" size={15} />],
  "change_request.cancelled": ["cancelled a change", "", <XCircle key="i" size={15} />],
  "change_request.expired": ["change expired", "", <XCircle key="i" size={15} />],
  "change_request.execution_started": ["started applying a change", "brand", <GitPullRequestArrow key="i" size={15} />],
  "change_request.executed": ["change applied in the vault", "success", <CheckCircle2 key="i" size={15} />],
  "change_request.execution_denied": ["change blocked at execution", "danger", <XCircle key="i" size={15} />],
  "change_request.break_glass": ["break-glass change", "danger", <Siren key="i" size={15} />],
  "secret.revealed": ["revealed a secret value", "warning", <Eye key="i" size={15} />],
  "secret.owner_set": ["changed a secret's owner", "", <KeyRound key="i" size={15} />],
  "rotation_policy.set": ["set a rotation policy", "brand", <RefreshCw key="i" size={15} />],
  "rotation_policy.deleted": ["removed a rotation policy", "", <RefreshCw key="i" size={15} />],
  "rotation.requested": ["requested a rotation", "brand", <RefreshCw key="i" size={15} />],
  "rotation.scheduled": ["rotation scheduled", "brand", <RefreshCw key="i" size={15} />],
  "rotation.started": ["rotation started", "brand", <RefreshCw key="i" size={15} />],
  "rotation.succeeded": ["secret rotated", "success", <CheckCircle2 key="i" size={15} />],
  "rotation.failed": ["rotation failed", "danger", <XCircle key="i" size={15} />],
  "rotation.overdue": ["rotation overdue: escalated", "warning", <Bell key="i" size={15} />],
  "connection.created": ["connected a cloud account", "brand", <Cloud key="i" size={15} />],
  "connection.synced": ["synced a connection", "", <Cloud key="i" size={15} />],
  "connection.sync_failed": ["connection sync failed", "danger", <Cloud key="i" size={15} />],
  "role_binding.created": ["granted a role", "", <Users key="i" size={15} />],
  "role_binding.removed": ["removed a role", "", <Users key="i" size={15} />],
  "invitation.created": ["invited a member", "", <UserPlus key="i" size={15} />],
  "invitation.accepted": ["joined the organization", "success", <UserPlus key="i" size={15} />],
  "invitation.revoked": ["revoked an invitation", "", <UserPlus key="i" size={15} />],
  "member.added": ["member added", "success", <UserPlus key="i" size={15} />],
  "member.removed": ["removed a member", "", <Users key="i" size={15} />],
  "member.role_changed": ["changed a member's role", "", <Users key="i" size={15} />],
  "organization.settings_changed": ["changed organization settings", "warning", <Users key="i" size={15} />],
  "api_token.created": ["created an API token", "", <KeyRound key="i" size={15} />],
  "api_token.revoked": ["revoked an API token", "", <KeyRound key="i" size={15} />],
  "notification_channel.created": ["added a notification channel", "", <Bell key="i" size={15} />],
  "notification_channel.deleted": ["removed a notification channel", "", <Bell key="i" size={15} />],
};

export function describe(e: AuditEvent): { text: string; tone: Tone; icon: ReactNode } {
  const k = known[e.action];
  if (e.action === "change_request.decision") {
    const approve = e.details.decision === "approve";
    return {
      text: approve ? "approved a change" : "rejected a change",
      tone: approve ? "success" : "danger",
      icon: approve ? <CheckCircle2 size={15} /> : <XCircle size={15} />,
    };
  }
  if (k) return { text: k[0], tone: k[1], icon: k[2] };
  return { text: e.action.replaceAll("_", " ").replace(".", ": "), tone: e.decision === "deny" ? "danger" : "", icon: <Activity size={15} /> };
}

export function actorName(e: AuditEvent, emails: Record<string, string>): string {
  if (e.actor_type === "system") return "SecretMesh";
  if (e.actor_id && emails[e.actor_id]) return emails[e.actor_id];
  return e.actor_type === "api_token" ? "API token" : "Someone";
}

const hidden = new Set(["policy_reasons"]);

export function ActivityItem({
  event: e,
  emails,
  href,
  now,
  showDetails,
}: {
  event: AuditEvent;
  emails: Record<string, string>;
  href: string;
  now: number;
  showDetails?: boolean;
}) {
  const d = describe(e);
  const details = Object.entries(e.details).filter(([k]) => showDetails || !hidden.has(k));
  return (
    <div className="tl-item">
      <span className={`tl-icon ${d.tone}`}>{d.icon}</span>
      <div className="tl-body">
        <div>
          <strong style={{ fontWeight: 550 }}>{actorName(e, emails)}</strong> <span className="muted">{d.text}</span>
          {e.resource_type === "secret" && /^[0-9a-f-]{36}$/.test(e.resource_id) && (
            <>
              {" · "}
              <Link href={`${href}/secrets/${e.resource_id}`} style={{ color: "var(--brand-text)" }}>
                view secret
              </Link>
            </>
          )}
          {e.change_request_id && (
            <>
              {" · "}
              <Link href={`${href}/changes?id=${e.change_request_id}`} style={{ color: "var(--brand-text)" }}>
                view request
              </Link>
            </>
          )}
        </div>
        <div className="meta" title={new Date(e.occurred_at).toLocaleString()}>
          #{e.seq} · {ago(e.occurred_at, now)}
        </div>
        {showDetails && details.length > 0 && (
          <div className="chips">
            {details.map(([k, v]) => (
              <span className="chip" key={k}>
                {k}: {v}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
