"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";
import { Cloud, KeyRound, Plus, Search, SlidersHorizontal } from "lucide-react";
import { api, type ChangeRequest, type Connection, type Environment, type Member, type Secret } from "@/lib/api";
import { useData, useOrg } from "@/components/org";
import { ChangeForm } from "@/components/change-form";
import {
  Avatar,
  Badge,
  Button,
  ButtonLink,
  Card,
  ClassBadge,
  Drawer,
  EmptyState,
  EnvBadge,
  PageHeader,
  Segmented,
  SkeletonRows,
  ago,
  useToast,
} from "@/components/ui";

interface Data {
  now: number;
  secrets: Secret[];
  environments: Environment[];
  connections: Connection[];
  emails: Record<string, string>;
}

type RotationFilter = "all" | "overdue" | "none";

export default function SecretsView() {
  const { base, href } = useOrg();
  const router = useRouter();
  const params = useSearchParams();
  const toast = useToast();
  const load = useCallback(async (): Promise<Data> => {
    const [s, e, c, m] = await Promise.all([
      api<{ secrets: Secret[] }>("GET", `${base}/secrets`),
      api<{ environments: Environment[] }>("GET", `${base}/environments`),
      api<{ connections: Connection[] }>("GET", `${base}/connections`),
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
    ]);
    const emails: Record<string, string> = {};
    for (const x of m.members) emails[x.user_id] = x.email;
    return { now: Date.now(), secrets: s.secrets, environments: e.environments, connections: c.connections, emails };
  }, [base]);
  const { data, run } = useData(load);
  const [q, setQ] = useState("");
  const [env, setEnv] = useState("all");
  const [rot, setRot] = useState<RotationFilter>("all");
  const [creating, setCreating] = useState(params.get("new") === "1");

  const secrets = useMemo(() => {
    if (!data) return [];
    const needle = q.trim().toLowerCase();
    return data.secrets.filter(
      (s) =>
        (!needle || s.name.toLowerCase().includes(needle) || s.description?.toLowerCase().includes(needle)) &&
        (env === "all" || s.environment_id === env) &&
        (rot === "all" ||
          (rot === "none" && !s.rotation_strategy) ||
          (rot === "overdue" && s.rotation_enabled && !!s.next_rotation_at && Date.parse(s.next_rotation_at) < data.now)),
    );
  }, [data, q, env, rot]);

  const envName = (id: string) => data?.environments.find((e) => e.id === id)?.name;
  const conn = (id: string) => data?.connections.find((c) => c.id === id);

  return (
    <>
      <PageHeader
        title="Secrets"
        description="Every secret SecretMesh governs across your cloud vaults. Values never leave the vault except when revealed by someone allowed to."
        actions={
          <Button variant="primary" icon={<Plus size={15} />} onClick={() => setCreating(true)}>
            New secret
          </Button>
        }
      />

      <Card flush>
        <div className="toolbar">
          <div className="input-icon" style={{ flex: "1 1 260px" }}>
            <Search size={15} />
            <input className="input" style={{ width: "100%" }} placeholder="Filter by name…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="select" value={env} onChange={(e) => setEnv(e.target.value)} aria-label="Environment">
            <option value="all">All environments</option>
            {data?.environments.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
          </select>
          <Segmented<RotationFilter>
            options={[
              { id: "all", label: "All", icon: <SlidersHorizontal size={13} /> },
              { id: "overdue", label: "Rotation overdue" },
              { id: "none", label: "No policy" },
            ]}
            value={rot}
            onChange={setRot}
          />
        </div>
        {!data ? (
          <SkeletonRows rows={6} />
        ) : data.secrets.length === 0 ? (
          <EmptyState
            icon={<KeyRound size={22} />}
            title="No secrets yet"
            action={
              <div style={{ display: "flex", gap: 8 }}>
                <Button variant="primary" icon={<Plus size={15} />} onClick={() => setCreating(true)}>
                  Create a secret
                </Button>
                <ButtonLink href={`${href}/settings?tab=connections`} icon={<Cloud size={15} />}>
                  Import from a cloud
                </ButtonLink>
              </div>
            }
          >
            Create one through an approved change, or connect a cloud account and sync to discover existing secrets.
          </EmptyState>
        ) : secrets.length === 0 ? (
          <EmptyState icon={<Search size={22} />} title="No matches">
            Try a different name or clear the filters.
          </EmptyState>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Secret</th>
                <th>Environment</th>
                <th>Classification</th>
                <th>Rotation</th>
                <th>Owner</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {secrets.map((s) => {
                const c = conn(s.connection_id);
                const overdue = s.rotation_enabled && s.next_rotation_at && Date.parse(s.next_rotation_at) < data.now;
                return (
                  <tr key={s.id} className="clickable" onClick={() => router.push(`${href}/secrets/${s.id}`)}>
                    <td>
                      <div className="cell-main">
                        <span className="cell-icon">
                          <KeyRound size={15} />
                        </span>
                        <div style={{ minWidth: 0 }}>
                          <strong>{s.name}</strong>
                          <small>
                            {c ? `${c.name} · ${c.provider.toUpperCase()}` : "connection"}
                            {s.origin === "discovered" && " · discovered"}
                          </small>
                        </div>
                      </div>
                    </td>
                    <td>
                      <EnvBadge kind={s.environment_kind} name={envName(s.environment_id)} />
                    </td>
                    <td>
                      <ClassBadge value={s.classification} />
                    </td>
                    <td>
                      {!s.rotation_strategy ? (
                        <span className="subtle">No policy</span>
                      ) : overdue ? (
                        <Badge tone="danger" dot>
                          Overdue {ago(s.next_rotation_at, data.now)}
                        </Badge>
                      ) : !s.rotation_enabled ? (
                        <Badge>Paused</Badge>
                      ) : (
                        <span title={s.next_rotation_at}>
                          <Badge tone={s.rotation_strategy === "native" ? "success" : "info"}>{s.rotation_strategy === "native" ? "Auto" : "Manual"}</Badge>{" "}
                          <span className="muted">{ago(s.next_rotation_at, data.now)}</span>
                        </span>
                      )}
                    </td>
                    <td>{s.owner_user_id && data.emails[s.owner_user_id] ? <Avatar email={data.emails[s.owner_user_id]} size="sm" /> : <span className="subtle">—</span>}</td>
                    <td className="muted">{ago(s.updated_at, data.now)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>

      <Drawer
        open={creating}
        onClose={() => setCreating(false)}
        icon={<KeyRound size={16} />}
        title="New secret"
        description="Requests a new secret. The value is staged in the provider until approved."
      >
        {data && (
          <ChangeForm
            operation="create"
            environments={data.environments}
            connections={data.connections.filter((c) => c.capabilities?.secret_create !== false)}
            onCancel={() => setCreating(false)}
            onSubmit={(body) =>
              run(async () => {
                const cr = await api<ChangeRequest>("POST", `${base}/change-requests`, body);
                setCreating(false);
                toast({
                  tone: "success",
                  title: cr.status === "pending" ? "Sent for approval" : "Change approved",
                  body:
                    cr.status === "pending"
                      ? `Needs ${cr.required_approvals} approval${cr.required_approvals === 1 ? "" : "s"}. Approvers have been notified.`
                      : "It is being applied in the vault now.",
                  action: (
                    <a className="btn sm" href={`${href}/changes?id=${cr.id}`}>
                      View request
                    </a>
                  ),
                });
              })
            }
          />
        )}
      </Drawer>
    </>
  );
}
