"use client";

import Link from "next/link";
import { useCallback } from "react";
import {
  AlarmClock,
  ArrowRight,
  CheckCircle2,
  FileClock,
  GitPullRequestArrow,
  KeyRound,
  PartyPopper,
  Plus,
  RefreshCw,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { api, type AuditEvent, type ChangeRequest, type Environment, type Member, type Secret } from "@/lib/api";
import { useOrg, useData } from "@/components/org";
import { ActivityItem } from "@/components/activity";
import { Avatar, Badge, ButtonLink, Card, EmptyState, EnvBadge, PageHeader, Skeleton, SkeletonRows, Stat, ago } from "@/components/ui";

interface Data {
  now: number;
  secrets: Secret[];
  environments: Environment[];
  changes: ChangeRequest[];
  events: AuditEvent[] | null;
  emails: Record<string, string>;
}

const envColors: Record<string, string> = { production: "var(--danger)", staging: "var(--warning)", development: "var(--info)" };
const classColors: Record<string, string> = { restricted: "var(--danger)", confidential: "var(--brand)", internal: "var(--text-subtle)" };

export default function DashboardView() {
  const { base, href, me, org } = useOrg();
  const load = useCallback(async (): Promise<Data> => {
    const [s, e, c, a, m] = await Promise.all([
      api<{ secrets: Secret[] }>("GET", `${base}/secrets`),
      api<{ environments: Environment[] }>("GET", `${base}/environments`),
      api<{ change_requests: ChangeRequest[] }>("GET", `${base}/change-requests`),
      api<{ events: AuditEvent[] }>("GET", `${base}/audit/events?limit=8`).catch(() => null),
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
    ]);
    const emails: Record<string, string> = {};
    for (const x of m.members) emails[x.user_id] = x.email;
    return { now: Date.now(), secrets: s.secrets, environments: e.environments, changes: c.change_requests, events: a?.events ?? null, emails };
  }, [base]);
  const { data } = useData(load);
  const first = (me.user.display_name || me.user.email).split(/[ @]/)[0];

  return (
    <>
      <PageHeader
        title={`Welcome back, ${first}`}
        description={`Here's what's happening in ${org.name}. Values stay in your cloud vaults; SecretMesh governs who changes them and when.`}
        actions={
          <>
            <ButtonLink href={`${href}/changes`} icon={<GitPullRequestArrow size={15} />}>
              Approvals
            </ButtonLink>
            <ButtonLink href={`${href}/secrets?new=1`} variant="primary" icon={<Plus size={15} />}>
              New secret
            </ButtonLink>
          </>
        }
      />
      {!data ? <DashboardSkeleton /> : <Dashboard data={data} />}
    </>
  );
}

function Dashboard({ data }: { data: Data }) {
  const { href, me } = useOrg();
  const { now, secrets, changes } = data;
  const review = changes.filter((c) => c.status === "pending" && c.requested_by !== me.user.id && !c.decisions.some((d) => d.approver_id === me.user.id));
  const overdue = secrets.filter((s) => s.rotation_enabled && s.next_rotation_at && Date.parse(s.next_rotation_at) < now);
  const withPolicy = secrets.filter((s) => s.rotation_strategy).length;
  const week = now - 7 * 86400_000;
  const applied = changes.filter((c) => c.status === "succeeded" && c.completed_at && Date.parse(c.completed_at) > week).length;
  const failedMine = changes.filter((c) => c.status === "failed" && c.requested_by === me.user.id && Date.parse(c.created_at) > week);
  const breakGlass = changes.filter((c) => c.break_glass && Date.parse(c.created_at) > week);
  const prod = secrets.filter((s) => s.environment_kind === "production").length;

  const byEnv = ["production", "staging", "development"].map((k) => ({ k, n: secrets.filter((s) => s.environment_kind === k).length }));
  const byClass = ["restricted", "confidential", "internal"].map((k) => ({ k, n: secrets.filter((s) => s.classification === k).length }));
  const total = Math.max(secrets.length, 1);
  const attention = review.length + overdue.length + failedMine.length + breakGlass.length;

  return (
    <>
      <div className="stats">
        <Stat label="Secrets governed" value={secrets.length} hint={`${prod} in production`} icon={<KeyRound size={15} />} href={`${href}/secrets`} />
        <Stat
          label="Awaiting your review"
          value={review.length}
          hint={review.length ? "Approvals need a decision" : "Nothing waiting"}
          icon={<GitPullRequestArrow size={15} />}
          tone={review.length ? "warning" : "success"}
          href={`${href}/changes`}
        />
        <Stat
          label="Rotation overdue"
          value={overdue.length}
          hint={`${withPolicy} of ${secrets.length} have a rotation policy`}
          icon={<AlarmClock size={15} />}
          tone={overdue.length ? "danger" : "success"}
          href={`${href}/rotation`}
        />
        <Stat label="Changes applied" value={applied} hint="In the last 7 days" icon={<CheckCircle2 size={15} />} tone="info" href={`${href}/changes?tab=all`} />
      </div>

      <div className="grid-3">
        <Card
          title="Needs attention"
          description={attention ? `${attention} item${attention === 1 ? "" : "s"}` : "You're all caught up"}
          flush
        >
          {attention === 0 ? (
            <EmptyState icon={<PartyPopper size={22} />} title="All clear">
              No approvals waiting, no overdue rotations and no failed changes this week.
            </EmptyState>
          ) : (
            <div className="rows">
              {breakGlass.map((c) => (
                <Link key={c.id} href={`${href}/changes?id=${c.id}`} className="row-item">
                  <span className="cell-icon" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>
                    <ShieldCheck size={16} />
                  </span>
                  <div className="grow">
                    <strong>Break-glass change to {c.secret_name}</strong>
                    <small>{c.reason}</small>
                  </div>
                  <Badge tone="danger">Review</Badge>
                </Link>
              ))}
              {review.map((c) => (
                <Link key={c.id} href={`${href}/changes?id=${c.id}`} className="row-item">
                  <Avatar email={data.emails[c.requested_by] ?? "?"} />
                  <div className="grow">
                    <strong>
                      {data.emails[c.requested_by]?.split("@")[0] ?? "Someone"} wants to {c.operation} {c.secret_name}
                    </strong>
                    <small>
                      {ago(c.created_at, now)} · {c.decisions.filter((d) => d.decision === "approve").length}/{c.required_approvals} approvals · expires{" "}
                      {ago(c.expires_at, now)}
                    </small>
                  </div>
                  <EnvBadge kind={c.environment_kind} />
                  <ArrowRight size={16} className="subtle" />
                </Link>
              ))}
              {overdue.map((s) => (
                <Link key={s.id} href={`${href}/secrets/${s.id}?tab=rotation`} className="row-item">
                  <span className="cell-icon" style={{ background: "var(--warning-soft)", color: "var(--warning)" }}>
                    <RefreshCw size={16} />
                  </span>
                  <div className="grow">
                    <strong>Rotate {s.name}</strong>
                    <small>
                      Due {ago(s.next_rotation_at, now)} · {s.rotation_strategy === "native" ? "automatic rotation did not complete" : "manual rotation"}
                    </small>
                  </div>
                  <Badge tone="danger" dot>
                    Overdue
                  </Badge>
                </Link>
              ))}
              {failedMine.map((c) => (
                <Link key={c.id} href={`${href}/changes?id=${c.id}`} className="row-item">
                  <span className="cell-icon" style={{ background: "var(--danger-soft)", color: "var(--danger)" }}>
                    <XCircle size={16} />
                  </span>
                  <div className="grow">
                    <strong>Your change to {c.secret_name} failed</strong>
                    <small>{c.failure_code}</small>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </Card>

        <Card title="Inventory" description="Where your secrets live">
          <div className="field">
            <span className="label">By environment</span>
            <div className="bar">
              {byEnv.map((b) => (
                <span key={b.k} style={{ width: `${(b.n / total) * 100}%`, background: envColors[b.k] }} />
              ))}
            </div>
            <div className="legend">
              {byEnv.map((b) => (
                <span key={b.k}>
                  <i style={{ background: envColors[b.k] }} />
                  {b.k} {b.n}
                </span>
              ))}
            </div>
          </div>
          <div className="field">
            <span className="label">By classification</span>
            <div className="bar">
              {byClass.map((b) => (
                <span key={b.k} style={{ width: `${(b.n / total) * 100}%`, background: classColors[b.k] }} />
              ))}
            </div>
            <div className="legend">
              {byClass.map((b) => (
                <span key={b.k}>
                  <i style={{ background: classColors[b.k] }} />
                  {b.k} {b.n}
                </span>
              ))}
            </div>
          </div>
          <div className="field">
            <span className="label">Rotation coverage</span>
            <div className="bar">
              <span style={{ width: `${(withPolicy / total) * 100}%`, background: "var(--success)" }} />
            </div>
            <span className="hint">
              {Math.round((withPolicy / total) * 100)}% of secrets have a rotation policy
            </span>
          </div>
        </Card>
      </div>

      <Card
        title="Recent activity"
        description="From the tamper-evident audit log"
        actions={
          <ButtonLink href={`${href}/audit`} variant="ghost" icon={<FileClock size={15} />}>
            Open audit log
          </ButtonLink>
        }
        flush
      >
        {data.events === null ? (
          <EmptyState icon={<FileClock size={22} />} title="Audit access needed">
            Ask an admin for the auditor or security admin role to see activity.
          </EmptyState>
        ) : data.events.length === 0 ? (
          <EmptyState icon={<FileClock size={22} />} title="No activity yet" />
        ) : (
          <div className="timeline" style={{ padding: "8px 0" }}>
            {data.events.map((e) => (
              <ActivityItem key={e.id} event={e} emails={data.emails} href={href} now={now} />
            ))}
          </div>
        )}
      </Card>
    </>
  );
}

function DashboardSkeleton() {
  return (
    <>
      <div className="stats">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="card stat">
            <Skeleton width="50%" />
            <Skeleton width="30%" height={28} />
          </div>
        ))}
      </div>
      <div className="card">
        <SkeletonRows rows={4} />
      </div>
    </>
  );
}
