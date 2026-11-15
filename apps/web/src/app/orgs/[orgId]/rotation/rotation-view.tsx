"use client";

import Link from "next/link";
import { useCallback, useState } from "react";
import { AlarmClock, CalendarCheck, CalendarClock, CircleSlash, KeyRound, RefreshCw } from "lucide-react";
import { api, type Secret } from "@/lib/api";
import { useData, useOrg } from "@/components/org";
import { Badge, Card, EmptyState, EnvBadge, PageHeader, SkeletonRows, Stat, Tabs, ago } from "@/components/ui";

type Group = "overdue" | "soon" | "later" | "none";

export default function RotationView() {
  const { base, href } = useOrg();
  const load = useCallback(async () => {
    const r = await api<{ secrets: Secret[] }>("GET", `${base}/secrets`);
    return { now: Date.now(), secrets: r.secrets };
  }, [base]);
  const { data } = useData(load);
  const [tab, setTab] = useState<Group>("overdue");

  const groups: Record<Group, Secret[]> = { overdue: [], soon: [], later: [], none: [] };
  if (data) {
    for (const s of data.secrets) {
      if (!s.rotation_strategy || !s.next_rotation_at) groups.none.push(s);
      else if (!s.rotation_enabled) groups.later.push(s);
      else {
        const due = Date.parse(s.next_rotation_at);
        if (due < data.now) groups.overdue.push(s);
        else if (due < data.now + 30 * 86400_000) groups.soon.push(s);
        else groups.later.push(s);
      }
    }
    for (const g of Object.values(groups)) g.sort((a, b) => Date.parse(a.next_rotation_at ?? "") - Date.parse(b.next_rotation_at ?? ""));
  }
  const coverage = data && data.secrets.length ? Math.round(((data.secrets.length - groups.none.length) / data.secrets.length) * 100) : 0;
  const list = groups[tab];

  return (
    <>
      <PageHeader
        title="Rotation"
        description="Rotation schedules across all secrets. Automatic policies run the provider's rotation function; manual ones remind owners and escalate when overdue."
      />
      <div className="stats">
        <Stat label="Overdue" value={data ? groups.overdue.length : "–"} icon={<AlarmClock size={15} />} tone={groups.overdue.length ? "danger" : "success"} hint="Escalating to owners and security" />
        <Stat label="Due in 30 days" value={data ? groups.soon.length : "–"} icon={<CalendarClock size={15} />} tone="warning" hint="Reminders are going out" />
        <Stat label="On schedule" value={data ? groups.later.length : "–"} icon={<CalendarCheck size={15} />} tone="success" />
        <Stat label="Coverage" value={data ? `${coverage}%` : "–"} icon={<RefreshCw size={15} />} tone="info" hint={`${groups.none.length} without a policy`} />
      </div>
      <Card flush>
        <div style={{ padding: "0 16px" }}>
          <Tabs<Group>
            value={tab}
            onChange={setTab}
            tabs={[
              { id: "overdue", label: "Overdue", count: groups.overdue.length },
              { id: "soon", label: "Due soon", count: groups.soon.length },
              { id: "later", label: "On schedule", count: groups.later.length },
              { id: "none", label: "No policy", count: groups.none.length },
            ]}
          />
        </div>
        {!data ? (
          <SkeletonRows rows={5} />
        ) : list.length === 0 ? (
          <EmptyState icon={tab === "none" ? <CircleSlash size={22} /> : <CalendarCheck size={22} />} title={tab === "overdue" ? "Nothing overdue" : "Nothing here"}>
            {tab === "overdue" ? "Every secret with a rotation policy is on schedule." : undefined}
          </EmptyState>
        ) : (
          <div className="rows">
            {list.map((s) => (
              <Link key={s.id} href={`${href}/secrets/${s.id}?tab=rotation`} className="row-item">
                <span className="cell-icon">
                  <KeyRound size={15} />
                </span>
                <div className="grow">
                  <strong>{s.name}</strong>
                  <small>
                    {s.rotation_strategy ? (s.rotation_strategy === "native" ? "Automatic" : "Manual") : "No rotation policy"}
                    {s.last_rotated_at && ` · last rotated ${ago(s.last_rotated_at, data.now)}`}
                  </small>
                </div>
                <EnvBadge kind={s.environment_kind} />
                {tab === "none" ? (
                  <Badge tone="brand">Set up →</Badge>
                ) : !s.rotation_enabled ? (
                  <Badge>Paused</Badge>
                ) : (
                  <Badge tone={tab === "overdue" ? "danger" : tab === "soon" ? "warning" : "success"} dot>
                    {tab === "overdue" ? "Overdue " : "Due "}
                    {ago(s.next_rotation_at, data.now)}
                  </Badge>
                )}
              </Link>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
