"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import {
  CheckCircle2,
  Clock,
  Fingerprint,
  GitPullRequestArrow,
  Inbox,
  KeyRound,
  Send,
  ShieldCheck,
  Siren,
  XCircle,
} from "lucide-react";
import { api, type ChangeRequest, type Environment, type Member } from "@/lib/api";
import { useData, useOrg } from "@/components/org";
import {
  Avatar,
  Badge,
  Button,
  Callout,
  Card,
  ClassBadge,
  CopyButton,
  Dialog,
  EmptyState,
  EnvBadge,
  PageHeader,
  SkeletonRows,
  StatusBadge,
  Tabs,
  ago,
  when,
} from "@/components/ui";

interface Data {
  now: number;
  changes: ChangeRequest[];
  environments: Environment[];
  emails: Record<string, string>;
}

type Tab = "review" | "mine" | "all" | "breakglass";

export default function ChangesView() {
  const { base, href, me, refreshCounts } = useOrg();
  const router = useRouter();
  const params = useSearchParams();
  const selected = params.get("id");
  const load = useCallback(async (): Promise<Data> => {
    const [crs, envs, members] = await Promise.all([
      api<{ change_requests: ChangeRequest[] }>("GET", `${base}/change-requests`),
      api<{ environments: Environment[] }>("GET", `${base}/environments`),
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
    ]);
    const emails: Record<string, string> = {};
    for (const m of members.members) emails[m.user_id] = m.email;
    return { now: Date.now(), changes: crs.change_requests, environments: envs.environments, emails };
  }, [base]);
  const { data, run } = useData(load);
  const [tab, setTab] = useState<Tab>((params.get("tab") as Tab) || (selected ? "all" : "review"));

  const lists = useMemo(() => {
    const all = data?.changes ?? [];
    return {
      review: all.filter((c) => c.status === "pending" && c.requested_by !== me.user.id && !c.decisions.some((d) => d.approver_id === me.user.id)),
      mine: all.filter((c) => c.requested_by === me.user.id),
      all,
      breakglass: all.filter((c) => c.break_glass),
    };
  }, [data, me.user.id]);
  const list = lists[tab];
  const current = data?.changes.find((c) => c.id === selected) ?? null;
  const select = (id: string) => router.replace(`?id=${id}&tab=${tab}`, { scroll: false });

  return (
    <>
      <PageHeader
        title="Approvals"
        description="Every change to a secret is reviewed here. Approvals are bound to the exact staged value: if anything changes, approvals no longer count."
      />
      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "review", label: "Needs your review", icon: <Inbox size={15} />, count: lists.review.length },
          { id: "mine", label: "Your requests", icon: <Send size={15} />, count: lists.mine.length },
          { id: "all", label: "All", icon: <GitPullRequestArrow size={15} /> },
          { id: "breakglass", label: "Break-glass", icon: <Siren size={15} />, count: lists.breakglass.length },
        ]}
      />
      <div className="split">
        <Card flush>
          {!data ? (
            <SkeletonRows rows={6} />
          ) : list.length === 0 ? (
            <EmptyState icon={tab === "review" ? <CheckCircle2 size={22} /> : <Inbox size={22} />} title={tab === "review" ? "Inbox zero" : "Nothing here"}>
              {tab === "review" ? "No changes are waiting for your decision." : undefined}
            </EmptyState>
          ) : (
            <div className="rows">
              {list.map((c) => {
                const approvals = c.decisions.filter((d) => d.decision === "approve").length;
                return (
                  <button key={c.id} className="row-item" aria-current={c.id === selected ? "true" : undefined} onClick={() => select(c.id)}>
                    <Avatar email={data.emails[c.requested_by] ?? "?"} />
                    <div className="grow">
                      <strong>
                        {c.operation[0].toUpperCase() + c.operation.slice(1)} {c.secret_name}
                      </strong>
                      <small>
                        {data.emails[c.requested_by]?.split("@")[0] ?? "someone"} · {ago(c.created_at, data.now)}
                        {c.status === "pending" && ` · ${approvals}/${c.required_approvals} approvals`}
                      </small>
                      <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
                        <EnvBadge kind={c.environment_kind} />
                        {c.break_glass && <Badge tone="danger">Break-glass</Badge>}
                      </div>
                    </div>
                    <StatusBadge status={c.status} />
                  </button>
                );
              })}
            </div>
          )}
        </Card>

        {current && data ? (
          <Detail
            key={current.id}
            c={current}
            data={data}
            href={href}
            mine={current.requested_by === me.user.id}
            decided={current.decisions.some((d) => d.approver_id === me.user.id)}
            onDecide={(decision, comment) =>
              run(
                () =>
                  api("POST", `${base}/change-requests/${current.id}/decisions`, {
                    decision,
                    binding_hash: current.binding_hash,
                    comment: comment || undefined,
                  }).then(refreshCounts),
                decision === "approve" ? "Approved" : "Rejected",
                decision === "approve" ? "If enough approvals are in, the change applies in the vault now." : "The staged value is being discarded.",
              )
            }
            onCancel={() => run(() => api("POST", `${base}/change-requests/${current.id}/cancel`), "Request cancelled")}
          />
        ) : (
          <Card>
            <EmptyState icon={<GitPullRequestArrow size={22} />} title="Select a request">
              Pick a change on the left to see its details, approvals and binding.
            </EmptyState>
          </Card>
        )}
      </div>
    </>
  );
}

function Detail({
  c,
  data,
  href,
  mine,
  decided,
  onDecide,
  onCancel,
}: {
  c: ChangeRequest;
  data: Data;
  href: string;
  mine: boolean;
  decided: boolean;
  onDecide: (decision: "approve" | "reject", comment: string) => Promise<boolean>;
  onCancel: () => Promise<boolean>;
}) {
  const [deciding, setDeciding] = useState<"approve" | "reject" | null>(null);
  const [reviewed, setReviewed] = useState(false);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const approvals = c.decisions.filter((d) => d.decision === "approve").length;
  const env = data.environments.find((e) => e.id === c.environment_id);
  const pct = c.required_approvals ? Math.min(100, (approvals / c.required_approvals) * 100) : 100;
  const name = (id: string) => data.emails[id] ?? id.slice(0, 8);

  return (
    <Card
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          {c.operation[0].toUpperCase() + c.operation.slice(1)} {c.secret_name}
        </span>
      }
      description={`Requested ${ago(c.created_at, data.now)} by ${name(c.requested_by)}`}
      actions={<StatusBadge status={c.status} />}
    >
      {c.break_glass && (
        <Callout tone="danger" icon={<Siren size={17} />} title="Break-glass change">
          Applied without prior approval. Review the justification after the fact.
        </Callout>
      )}
      {c.failure_code && <Callout tone="danger" title="Not applied">{c.failure_code.replaceAll("_", " ")}</Callout>}

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        <EnvBadge kind={c.environment_kind} name={env?.name} />
        <ClassBadge value={c.classification} />
        {c.secret_id && (
          <Link href={`${href}/secrets/${c.secret_id}`}>
            <Badge tone="brand">
              <KeyRound size={11} /> Open secret
            </Badge>
          </Link>
        )}
      </div>

      {c.reason && (
        <div className="field">
          <span className="label">Reason</span>
          <div className="callout">{c.reason}</div>
        </div>
      )}

      <div className="field">
        <span className="label">
          Approvals {approvals} of {c.required_approvals}
        </span>
        <div className="bar">
          <span style={{ width: `${pct}%`, background: pct >= 100 ? "var(--success)" : "var(--warning)" }} />
        </div>
      </div>

      <div className="field">
        <span className="label">
          <Fingerprint size={14} style={{ verticalAlign: -2 }} /> Binding hash
        </span>
        <div className="hash">
          <span style={{ flex: 1 }}>{c.binding_hash}</span>
          <CopyButton value={c.binding_hash} label="" />
        </div>
        <span className="hint">Covers the target, operation, staged value and expiry. Your approval applies to exactly this.</span>
      </div>

      <div className="timeline" style={{ margin: "0 -20px" }}>
        <div className="tl-item">
          <span className="tl-icon brand">
            <Send size={14} />
          </span>
          <div className="tl-body">
            <strong style={{ fontWeight: 550 }}>{name(c.requested_by)}</strong> <span className="muted">requested this change</span>
            <div className="meta">{when(c.created_at)}</div>
          </div>
        </div>
        {c.decisions.map((d) => (
          <div className="tl-item" key={d.approver_id}>
            <span className={`tl-icon ${d.decision === "approve" ? "success" : "danger"}`}>
              {d.decision === "approve" ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            </span>
            <div className="tl-body">
              <strong style={{ fontWeight: 550 }}>{name(d.approver_id)}</strong>{" "}
              <span className="muted">{d.decision === "approve" ? "approved" : "rejected"}</span>{" "}
              {d.mfa && (
                <Badge tone="success">
                  <ShieldCheck size={11} /> MFA
                </Badge>
              )}
              <div className="meta">{when(d.created_at)}</div>
              {d.comment && <div className="callout" style={{ marginTop: 6, padding: "8px 12px" }}>{d.comment}</div>}
            </div>
          </div>
        ))}
        {c.completed_at ? (
          <div className="tl-item">
            <span className={`tl-icon ${c.status === "succeeded" ? "success" : "danger"}`}>
              {c.status === "succeeded" ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
            </span>
            <div className="tl-body">
              <span className="muted">{c.status === "succeeded" ? "Applied in the vault" : `Ended: ${c.status}`}</span>
              {c.provider_version_id && <span className="chip" style={{ marginLeft: 6 }}>version {c.provider_version_id}</span>}
              <div className="meta">{when(c.completed_at)}</div>
            </div>
          </div>
        ) : (
          c.status === "pending" && (
            <div className="tl-item">
              <span className="tl-icon warning">
                <Clock size={14} />
              </span>
              <div className="tl-body">
                <span className="muted">Waiting for approval · expires {ago(c.expires_at, data.now)}</span>
              </div>
            </div>
          )
        )}
      </div>

      {c.status === "pending" && !mine && !decided && (
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <Button icon={<XCircle size={15} />} onClick={() => setDeciding("reject")}>
            Reject
          </Button>
          <Button variant="primary" icon={<CheckCircle2 size={15} />} onClick={() => setDeciding("approve")}>
            Approve
          </Button>
        </div>
      )}
      {c.status === "pending" && mine && <Callout tone="info">You can&apos;t approve your own request.</Callout>}
      {mine && (c.status === "pending" || c.status === "approved") && (
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <Button variant="ghost" onClick={() => void onCancel()}>
            Cancel my request
          </Button>
        </div>
      )}

      <Dialog
        open={deciding !== null}
        onClose={() => setDeciding(null)}
        icon={deciding === "approve" ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
        title={deciding === "approve" ? `Approve ${c.operation} of ${c.secret_name}?` : `Reject ${c.operation} of ${c.secret_name}?`}
        description={deciding === "approve" ? "Needs a recent sign-in, and MFA for production changes." : "The staged value is discarded from the vault."}
        footer={
          <>
            <Button onClick={() => setDeciding(null)}>Cancel</Button>
            <Button
              variant={deciding === "approve" ? "primary" : "danger"}
              loading={busy}
              disabled={deciding === "approve" && !reviewed}
              onClick={async () => {
                if (!deciding) return;
                setBusy(true);
                const ok = await onDecide(deciding, comment);
                setBusy(false);
                if (ok) setDeciding(null);
              }}
            >
              {deciding === "approve" ? "Approve" : "Reject"}
            </Button>
          </>
        }
      >
        <div className="form">
          {deciding === "approve" && (
            <label className="check">
              <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} />
              <span>
                I reviewed this change and its reason. My approval is bound to hash <span className="mono">{c.binding_hash.slice(0, 12)}…</span>
              </span>
            </label>
          )}
          <textarea className="textarea" placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000} />
        </div>
      </Dialog>
    </Card>
  );
}
