"use client";

import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Eye,
  EyeOff,
  GitPullRequestArrow,
  History,
  Info,
  KeyRound,
  Lock,
  Pencil,
  RefreshCw,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { api, type ChangeRequest, type Connection, type Member, type Secret, type SecretVersion } from "@/lib/api";
import { useApiError, useData, useOrg } from "@/components/org";
import { ChangeForm } from "@/components/change-form";
import { RotationPanel } from "@/components/rotation-panel";
import {
  Avatar,
  Badge,
  Button,
  Callout,
  Card,
  ClassBadge,
  CopyButton,
  Dialog,
  Drawer,
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
  secret: Secret;
  connection?: Connection;
  changes: ChangeRequest[];
  members: Member[];
}

type Tab = "overview" | "rotation" | "versions" | "history";

/** How long a revealed value stays on screen. */
const REVEAL_SECONDS = 30;

export default function SecretView() {
  const { base, href } = useOrg();
  const { secretId } = useParams<{ secretId: string }>();
  const params = useSearchParams();
  const router = useRouter();
  const path = `${base}/secrets/${encodeURIComponent(secretId)}`;
  const load = useCallback(async (): Promise<Data> => {
    const [secret, conns, crs, members] = await Promise.all([
      api<Secret>("GET", path),
      api<{ connections: Connection[] }>("GET", `${base}/connections`),
      api<{ change_requests: ChangeRequest[] }>("GET", `${base}/change-requests`),
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
    ]);
    return {
      now: Date.now(),
      secret,
      connection: conns.connections.find((c) => c.id === secret.connection_id),
      changes: crs.change_requests.filter((c) => c.secret_id === secret.id),
      members: members.members,
    };
  }, [base, path]);
  const { data, error, run, reload } = useData(load);
  const [tab, setTab] = useState<Tab>((params.get("tab") as Tab) || "overview");
  const [revealing, setRevealing] = useState(false);
  const [changing, setChanging] = useState<"update" | "delete" | null>(null);

  if (error) {
    return (
      <Card>
        <EmptyState icon={<KeyRound size={22} />} title="Secret not found">
          It may have been deleted, or you don&apos;t have access to its environment.
        </EmptyState>
      </Card>
    );
  }
  if (!data) {
    return (
      <Card>
        <SkeletonRows rows={5} />
      </Card>
    );
  }

  const { secret: s, connection: c } = data;
  const caps = c?.capabilities;
  const open = data.changes.find((x) => ["pending", "approved", "executing"].includes(x.status));
  const emails: Record<string, string> = {};
  for (const m of data.members) emails[m.user_id] = m.email;
  const active = s.status === "active";

  return (
    <>
      <PageHeader
        crumbs={[{ href: `${href}/secrets`, label: "Secrets" }]}
        title={
          <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
            <span className="cell-icon">
              <KeyRound size={16} />
            </span>
            {s.name}
          </span>
        }
        badges={
          <>
            <EnvBadge kind={s.environment_kind} />
            <ClassBadge value={s.classification} />
            {!active && <Badge tone="danger">Deleted</Badge>}
          </>
        }
        description={s.description || `${c?.name ?? "Connection"} · ${c?.provider.toUpperCase() ?? ""}${s.origin === "discovered" ? " · discovered in the provider" : ""}`}
        actions={
          active && (
            <>
              {caps?.secret_reveal && (
                <Button icon={<Eye size={15} />} onClick={() => setRevealing(true)}>
                  Reveal
                </Button>
              )}
              {caps?.secret_delete !== false && (
                <Button icon={<Trash2 size={15} />} onClick={() => setChanging("delete")} disabled={!!open}>
                  Delete
                </Button>
              )}
              {caps?.secret_update !== false && (
                <Button variant="primary" icon={<Pencil size={15} />} onClick={() => setChanging("update")} disabled={!!open}>
                  Change value
                </Button>
              )}
            </>
          )
        }
      />

      {open && (
        <Callout tone="info" icon={<GitPullRequestArrow size={17} />} title={`A ${open.operation} is ${open.status === "pending" ? "waiting for approval" : open.status}`}>
          Only one change per secret can be open at a time.{" "}
          <Link href={`${href}/changes?id=${open.id}`} style={{ color: "var(--brand-text)", fontWeight: 550 }}>
            View request →
          </Link>
        </Callout>
      )}

      <Tabs<Tab>
        value={tab}
        onChange={(t) => {
          setTab(t);
          router.replace(`?tab=${t}`, { scroll: false });
        }}
        tabs={[
          { id: "overview", label: "Overview", icon: <Info size={15} /> },
          { id: "rotation", label: "Rotation", icon: <RefreshCw size={15} /> },
          { id: "versions", label: "Versions", icon: <History size={15} /> },
          { id: "history", label: "Change history", icon: <Activity size={15} />, count: data.changes.length },
        ]}
      />

      {tab === "overview" && (
        <div className="grid-3">
          <Card title="Details">
            <dl className="kv">
              <dt>Environment</dt>
              <dd>
                <EnvBadge kind={s.environment_kind} />
              </dd>
              <dt>Classification</dt>
              <dd>
                <ClassBadge value={s.classification} />
              </dd>
              <dt>Connection</dt>
              <dd>
                {c?.name} <span className="subtle">({c?.provider})</span>
              </dd>
              <dt>Provider reference</dt>
              <dd className="mono">{s.provider_ref}</dd>
              <dt>Current version</dt>
              <dd className="mono">{s.current_version ?? "—"}</dd>
              <dt>Owner</dt>
              <dd>
                {s.owner_user_id && emails[s.owner_user_id] ? (
                  <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}>
                    <Avatar email={emails[s.owner_user_id]} size="sm" />
                    {emails[s.owner_user_id]}
                  </span>
                ) : (
                  <span className="subtle">No owner, set one under Rotation</span>
                )}
              </dd>
              <dt>Last rotated</dt>
              <dd>{s.last_rotated_at ? `${ago(s.last_rotated_at, data.now)}` : "Never recorded"}</dd>
              <dt>Last seen in provider</dt>
              <dd>{when(s.last_seen_at)}</dd>
              <dt>Created</dt>
              <dd>{when(s.created_at)}</dd>
            </dl>
          </Card>
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <Card title="Security">
              <div className="rows" style={{ margin: "-8px -20px" }}>
                <div className="row-item">
                  <Lock size={16} className="subtle" />
                  <div className="grow">
                    <strong>Value stays in the vault</strong>
                    <small>SecretMesh stores no values</small>
                  </div>
                </div>
                <div className="row-item">
                  <ShieldAlert size={16} className="subtle" />
                  <div className="grow">
                    <strong>{s.environment_kind === "production" ? "Approval + MFA required" : "Approval per policy"}</strong>
                    <small>Changes are reviewed before they apply</small>
                  </div>
                </div>
                <div className="row-item">
                  <RefreshCw size={16} className="subtle" />
                  <div className="grow">
                    <strong>{s.rotation_strategy ? (s.rotation_strategy === "native" ? "Automatic rotation" : "Manual rotation") : "No rotation policy"}</strong>
                    <small>{s.next_rotation_at ? `Next due ${ago(s.next_rotation_at, data.now)}` : "Set one under Rotation"}</small>
                  </div>
                </div>
              </div>
            </Card>
            {s.tags && Object.keys(s.tags).length > 0 && (
              <Card title="Tags">
                <div className="chips" style={{ marginTop: 0 }}>
                  {Object.entries(s.tags).map(([k, v]) => (
                    <span className="chip" key={k}>
                      {k}={v}
                    </span>
                  ))}
                </div>
              </Card>
            )}
          </div>
        </div>
      )}

      {tab === "rotation" && active && (
        <RotationPanel base={base} secret={s} nativeAvailable={!!caps?.native_rotation} members={data.members} onChanged={reload} />
      )}

      {tab === "versions" && <Versions path={path} versioning={!!caps?.versioning} now={data.now} />}

      {tab === "history" && (
        <Card flush>
          {data.changes.length === 0 ? (
            <EmptyState icon={<GitPullRequestArrow size={22} />} title="No changes yet" />
          ) : (
            <div className="rows">
              {data.changes.map((x) => (
                <Link key={x.id} href={`${href}/changes?id=${x.id}`} className="row-item">
                  <Avatar email={emails[x.requested_by] ?? "?"} />
                  <div className="grow">
                    <strong>
                      {x.operation[0].toUpperCase() + x.operation.slice(1)} by {emails[x.requested_by] ?? "someone"}
                    </strong>
                    <small>
                      {ago(x.created_at, data.now)}
                      {x.reason && ` · ${x.reason}`}
                    </small>
                  </div>
                  {x.break_glass && <Badge tone="danger">Break-glass</Badge>}
                  <StatusBadge status={x.status} />
                </Link>
              ))}
            </div>
          )}
        </Card>
      )}

      <RevealDialog open={revealing} onClose={() => setRevealing(false)} path={`${path}/reveal`} secret={s} />

      <Drawer
        open={changing !== null}
        onClose={() => setChanging(null)}
        icon={changing === "delete" ? <Trash2 size={16} /> : <Pencil size={16} />}
        title={changing === "delete" ? `Delete ${s.name}` : `Change ${s.name}`}
        description={changing === "delete" ? "Requests deletion. It applies after the required approvals." : "The new value is staged in the vault and goes live after approval."}
      >
        {changing && (
          <ChangeForm
            operation={changing}
            secretId={s.id}
            onCancel={() => setChanging(null)}
            onSubmit={(body) =>
              run(async () => {
                await api<ChangeRequest>("POST", `${base}/change-requests`, body);
                setChanging(null);
              }, "Change requested", "Approvers have been notified.")
            }
          />
        )}
      </Drawer>
    </>
  );
}

function Versions({ path, versioning, now }: { path: string; versioning: boolean; now: number }) {
  const [versions, setVersions] = useState<SecretVersion[] | null>(null);
  const onError = useApiError();
  useEffect(() => {
    if (!versioning) return;
    api<{ versions: SecretVersion[] }>("GET", `${path}/versions`).then(
      (r) => setVersions(r.versions),
      (e) => {
        onError(e);
        setVersions([]);
      },
    );
  }, [path, versioning, onError]);
  if (!versioning) {
    return (
      <Card>
        <EmptyState icon={<History size={22} />} title="Versions not available">
          This provider does not keep versions.
        </EmptyState>
      </Card>
    );
  }
  return (
    <Card title="Versions" description="Read live from the provider" flush>
      {versions === null ? (
        <SkeletonRows rows={3} />
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Labels</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {versions.map((v) => (
              <tr key={v.id}>
                <td className="mono">{v.id}</td>
                <td>
                  <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
                    {v.stages.length === 0 && <span className="subtle">—</span>}
                    {v.stages.map((st) => (
                      <Badge key={st} tone={st === "AWSCURRENT" || st === "current" ? "success" : st.includes("PENDING") ? "warning" : "neutral"}>
                        {st}
                      </Badge>
                    ))}
                  </span>
                </td>
                <td className="muted">{v.created_at ? ago(v.created_at, now) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}

/**
 * Shows the current value for REVEAL_SECONDS. The value lives only in this
 * component's state: never in storage, the URL or logs, and it is dropped
 * when the dialog closes or the tab is hidden.
 */
function RevealDialog({ open, onClose, path, secret }: { open: boolean; onClose: () => void; path: string; secret: Secret }) {
  return open ? <RevealInner onClose={onClose} path={path} secret={secret} /> : null;
}

function RevealInner({ onClose, path, secret }: { onClose: () => void; path: string; secret: Secret }) {
  const [value, setValue] = useState<string | null>(null);
  const [version, setVersion] = useState("");
  const [hideAt, setHideAt] = useState(0);
  const [now, setNow] = useState(0);
  const [busy, setBusy] = useState(false);
  const [masked, setMasked] = useState(false);
  const onError = useApiError();

  useEffect(() => {
    if (value === null) return;
    const expire = setTimeout(() => setValue(null), REVEAL_SECONDS * 1000);
    const tick = setInterval(() => setNow(Date.now()), 1000);
    const hide = () => {
      if (document.visibilityState === "hidden") setValue(null);
    };
    document.addEventListener("visibilitychange", hide);
    return () => {
      clearTimeout(expire);
      clearInterval(tick);
      document.removeEventListener("visibilitychange", hide);
    };
  }, [value]);

  async function reveal() {
    setBusy(true);
    try {
      const r = await api<{ value: string; version_id: string }>("POST", path);
      const t = Date.now();
      setNow(t);
      setHideAt(t + REVEAL_SECONDS * 1000);
      setVersion(r.version_id);
      setValue(r.value);
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  const left = Math.max(0, Math.ceil((hideAt - now) / 1000));
  const strong = secret.environment_kind === "production" || secret.classification === "restricted";
  return (
    <Dialog
      open
      onClose={onClose}
      icon={<Eye size={16} />}
      title={`Reveal ${secret.name}`}
      description="Reads the current value from the provider. Every reveal is recorded in the audit log."
      footer={
        value === null ? (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" loading={busy} icon={<Eye size={15} />} onClick={reveal}>
              Reveal value
            </Button>
          </>
        ) : (
          <>
            <Button icon={masked ? <Eye size={15} /> : <EyeOff size={15} />} onClick={() => setMasked(!masked)}>
              {masked ? "Show" : "Mask"}
            </Button>
            <CopyButton value={value} />
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          </>
        )
      }
    >
      {value === null ? (
        <div className="form">
          <div className="secret-box masked">••••••••••••••••••••</div>
          <Callout tone="info">
            Needs the secret_admin role and a sign-in within the last 5 minutes{strong ? ", with MFA for production or restricted secrets" : ""}.
            The value hides after {REVEAL_SECONDS} seconds.
          </Callout>
        </div>
      ) : (
        <div className="form">
          <div className={masked ? "secret-box masked" : "secret-box"}>{masked ? "•".repeat(Math.min(value.length, 24)) : value}</div>
          <div className="countdown">
            <span style={{ width: `${(left / REVEAL_SECONDS) * 100}%` }} />
          </div>
          <span className="subtle" style={{ fontSize: 12.5 }}>
            Version <span className="mono">{version}</span> · hides in {left}s
          </span>
        </div>
      )}
    </Dialog>
  );
}
