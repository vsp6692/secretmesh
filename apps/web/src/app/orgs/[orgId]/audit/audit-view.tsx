"use client";

import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FileClock, Link2, Search, ShieldCheck, ShieldX } from "lucide-react";
import { api, type AuditEvent, type AuditVerification, type Member } from "@/lib/api";
import { useApiError, useData, useOrg } from "@/components/org";
import { ActivityItem, actorName, describe } from "@/components/activity";
import { Badge, Button, Card, EmptyState, PageHeader, Segmented, SkeletonRows } from "@/components/ui";

const PAGE = 50;

type Decision = "all" | "allow" | "deny";

export default function AuditView() {
  const { base, href } = useOrg();
  const params = useSearchParams();
  const [cursors, setCursors] = useState<number[]>([]);
  const cursor = cursors.at(-1);
  const load = useCallback(async () => {
    const q = new URLSearchParams({ limit: String(PAGE) });
    if (cursor !== undefined) q.set("before", String(cursor));
    const [ev, m] = await Promise.all([
      api<{ events: AuditEvent[] }>("GET", `${base}/audit/events?${q}`),
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
    ]);
    const emails: Record<string, string> = {};
    for (const x of m.members) emails[x.user_id] = x.email;
    return { now: Date.now(), events: ev.events, emails };
  }, [base, cursor]);
  const { data, error } = useData(load);
  const [q, setQ] = useState("");
  const [decision, setDecision] = useState<Decision>("all");

  const events = useMemo(() => {
    if (!data) return [];
    const needle = q.trim().toLowerCase();
    return data.events.filter((e) => {
      if (decision !== "all" && e.decision !== decision) return false;
      if (!needle) return true;
      const hay = [e.action, describe(e).text, actorName(e, data.emails), e.resource_id, ...Object.values(e.details)].join(" ").toLowerCase();
      return hay.includes(needle);
    });
  }, [data, q, decision]);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every action, hash-chained and signed. Tampering with any event breaks the chain and is detected by verification."
      />
      <Integrity base={base} auto={params.get("verify") === "1"} />
      <Card flush>
        <div className="toolbar">
          <div className="input-icon" style={{ flex: "1 1 260px" }}>
            <Search size={15} />
            <input className="input" style={{ width: "100%" }} placeholder="Search actions, people, resources…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <Segmented<Decision>
            options={[
              { id: "all", label: "All" },
              { id: "allow", label: "Allowed" },
              { id: "deny", label: "Denied" },
            ]}
            value={decision}
            onChange={setDecision}
          />
          <div style={{ display: "flex", gap: 6, marginLeft: "auto" }}>
            <Button size="sm" icon={<ChevronLeft size={14} />} disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>
              Newer
            </Button>
            <Button
              size="sm"
              disabled={!data || data.events.length < PAGE}
              onClick={() => data && setCursors([...cursors, data.events[data.events.length - 1].seq])}
            >
              Older <ChevronRight size={14} />
            </Button>
          </div>
        </div>
        {error ? (
          <EmptyState icon={<FileClock size={22} />} title="Audit access needed">
            The audit log is visible to auditors and security admins.
          </EmptyState>
        ) : !data ? (
          <SkeletonRows rows={8} />
        ) : events.length === 0 ? (
          <EmptyState icon={<Search size={22} />} title="No matching events" />
        ) : (
          <div className="timeline" style={{ padding: "8px 0" }}>
            {events.map((e) => (
              <ActivityItem key={e.id} event={e} emails={data.emails} href={href} now={data.now} showDetails />
            ))}
          </div>
        )}
      </Card>
    </>
  );
}

function Integrity({ base, auto }: { base: string; auto: boolean }) {
  const [v, setV] = useState<AuditVerification | null>(null);
  const [busy, setBusy] = useState(false);
  const onError = useApiError();

  const verify = useCallback(() => {
    setBusy(true);
    api<AuditVerification>("GET", `${base}/audit/verification`)
      .then(setV, onError)
      .finally(() => setBusy(false));
  }, [base, onError]);

  useEffect(() => {
    if (!auto) return;
    const t = setTimeout(verify, 0);
    return () => clearTimeout(t);
  }, [auto, verify]);

  return (
    <Card
      icon={<span className="cell-icon">{v && !v.valid ? <ShieldX size={16} /> : <ShieldCheck size={16} />}</span>}
      title="Integrity"
      description={
        v
          ? v.valid
            ? `Verified ${v.events_checked} events and ${v.checkpoints_verified} signed checkpoints`
            : `Verification failed${v.first_invalid_seq !== undefined ? ` at event #${v.first_invalid_seq}` : ""}: ${v.problem ?? "chain broken"}`
          : "Recompute the hash chain and check every signed checkpoint"
      }
      actions={
        <Button variant={v ? "secondary" : "primary"} loading={busy} icon={<ShieldCheck size={15} />} onClick={verify}>
          {v ? "Verify again" : "Verify now"}
        </Button>
      }
    >
      {v && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Badge tone={v.valid ? "success" : "danger"} dot>
            {v.valid ? "Chain intact" : "Tampering detected"}
          </Badge>
          <Badge outline>Head #{v.head_seq}</Badge>
          <Badge outline>
            <Link2 size={11} /> Last checkpoint {v.last_checkpoint_seq !== undefined ? `#${v.last_checkpoint_seq}` : "none yet"}
          </Badge>
          <Badge tone={v.last_exported_seq !== undefined ? "info" : "neutral"} outline>
            {v.last_exported_seq !== undefined ? `Exported to Object Lock up to #${v.last_exported_seq}` : "No off-site export configured"}
          </Badge>
        </div>
      )}
    </Card>
  );
}
