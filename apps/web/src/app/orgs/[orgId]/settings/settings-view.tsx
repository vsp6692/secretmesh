"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useState, type FormEvent, type ReactNode } from "react";
import {
  Bell,
  Building2,
  Cloud,
  KeyRound,
  Layers,
  Mail,
  MessageSquare,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";
import {
  api,
  BINDING_ROLES,
  SCOPES,
  type ApiToken,
  type BindingRole,
  type Connection,
  type Environment,
  type EnvironmentKind,
  type Invitation,
  type Member,
  type NotificationChannel,
  type NotificationDelivery,
  type Organization,
  type Role,
  type RoleBinding,
  type Scope,
  type Secret,
  type SyncResult,
} from "@/lib/api";
import { useData, useOrg } from "@/components/org";
import {
  Avatar,
  Badge,
  Button,
  Callout,
  Card,
  CopyButton,
  Drawer,
  EmptyState,
  EnvBadge,
  Field,
  PageHeader,
  Segmented,
  SkeletonRows,
  Tabs,
  ago,
  useConfirm,
  when,
} from "@/components/ui";

type Tab = "general" | "members" | "access" | "environments" | "connections" | "notifications";
const TABS: Tab[] = ["general", "members", "access", "environments", "connections", "notifications"];

interface Data {
  now: number;
  org: Organization;
  members: Member[];
  invitations: Invitation[];
  tokens: ApiToken[];
  environments: Environment[];
  connections: Connection[];
  bindings: RoleBinding[] | null; // null when the viewer may not list them
  channels: NotificationChannel[];
  emailAvailable: boolean;
  deliveries: NotificationDelivery[] | null; // null without notifications.manage
  secrets: Secret[];
}

type Run = (action: () => Promise<unknown>, success?: string, body?: string) => Promise<boolean>;

const roleLabel: Record<Role, string> = { org_admin: "Admin", member: "Member" };

const roleHelp: Record<BindingRole, string> = {
  cloud_admin: "Manage connections and sync",
  security_admin: "Manage approval policy and notifications",
  secret_admin: "Propose changes, reveal values, manage rotation",
  developer: "Propose changes",
  approver: "Approve or reject changes",
  auditor: "Read the audit log",
  break_glass: "Emergency changes without prior approval",
};

const roleTone: Record<BindingRole, "brand" | "info" | "warning" | "danger" | "success" | "neutral"> = {
  cloud_admin: "info",
  security_admin: "brand",
  secret_admin: "warning",
  developer: "neutral",
  approver: "success",
  auditor: "neutral",
  break_glass: "danger",
};

export default function SettingsView() {
  const { base } = useOrg();
  const params = useSearchParams();
  const router = useRouter();
  const initial = params.get("tab") as Tab;
  const [tab, setTab] = useState<Tab>(TABS.includes(initial) ? initial : "general");

  const load = useCallback(async (): Promise<Data> => {
    const org = await api<Organization>("GET", base);
    const isAdmin = org.role === "org_admin";
    const [m, inv, tok, e, c, b, ch, d, s] = await Promise.all([
      api<{ members: Member[] }>("GET", `${base}/members`).catch(() => ({ members: [] as Member[] })),
      isAdmin ? api<{ invitations: Invitation[] }>("GET", `${base}/invitations`) : { invitations: [] },
      isAdmin ? api<{ tokens: ApiToken[] }>("GET", `${base}/api-tokens`) : { tokens: [] },
      api<{ environments: Environment[] }>("GET", `${base}/environments`),
      api<{ connections: Connection[] }>("GET", `${base}/connections`),
      api<{ role_bindings: RoleBinding[] }>("GET", `${base}/role-bindings`).catch(() => null),
      api<{ channels: NotificationChannel[]; email_available: boolean }>("GET", `${base}/notification-channels`),
      api<{ deliveries: NotificationDelivery[] }>("GET", `${base}/notifications`).catch(() => null),
      api<{ secrets: Secret[] }>("GET", `${base}/secrets`),
    ]);
    return {
      now: Date.now(),
      org,
      members: m.members,
      invitations: inv.invitations,
      tokens: tok.tokens,
      environments: e.environments,
      connections: c.connections,
      bindings: b?.role_bindings ?? null,
      channels: ch.channels,
      emailAvailable: ch.email_available,
      deliveries: d?.deliveries ?? null,
      secrets: s.secrets,
    };
  }, [base]);
  const { data, run } = useData(load);

  const select = (t: Tab) => {
    setTab(t);
    router.replace(`?tab=${t}`, { scroll: false });
  };

  return (
    <>
      <PageHeader title="Settings" description="Organization, people, access, environments, cloud connections and notifications." />
      <Tabs<Tab>
        value={tab}
        onChange={select}
        tabs={[
          { id: "general", label: "General", icon: <Building2 size={15} /> },
          { id: "members", label: "Members", icon: <Users size={15} />, count: data?.members.length },
          { id: "access", label: "Access", icon: <ShieldCheck size={15} />, count: data?.bindings?.length },
          { id: "environments", label: "Environments", icon: <Layers size={15} />, count: data?.environments.length },
          { id: "connections", label: "Connections", icon: <Cloud size={15} />, count: data?.connections.length },
          { id: "notifications", label: "Notifications", icon: <Bell size={15} />, count: data?.channels.length },
        ]}
      />
      <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 20 }}>
        {!data ? (
          <Card>
            <SkeletonRows rows={5} />
          </Card>
        ) : (
          <>
            {tab === "general" && <General data={data} base={base} run={run} />}
            {tab === "members" && <Members data={data} base={base} run={run} />}
            {tab === "access" && <Access data={data} base={base} run={run} />}
            {tab === "environments" && <Environments data={data} base={base} run={run} />}
            {tab === "connections" && <Connections data={data} base={base} run={run} />}
            {tab === "notifications" && <Notifications data={data} base={base} run={run} />}
          </>
        )}
      </div>
    </>
  );
}

interface SectionProps {
  data: Data;
  base: string;
  run: Run;
}

function envName(data: Data, id?: string) {
  return id ? (data.environments.find((e) => e.id === id)?.name ?? "?") : "All environments";
}

// ---------- General ----------

function General({ data, base, run }: SectionProps) {
  const { org } = data;
  const isAdmin = org.role === "org_admin";
  return (
    <>
      <Card icon={<span className="cell-icon"><Building2 size={16} /></span>} title="Organization" description="Basic details of this workspace.">
        <dl className="kv">
          <dt>Name</dt>
          <dd>{org.name}</dd>
          <dt>Slug</dt>
          <dd className="mono">{org.slug}</dd>
          <dt>ID</dt>
          <dd style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="mono subtle">{org.id}</span>
            <CopyButton value={org.id} />
          </dd>
          <dt>Your role</dt>
          <dd>
            <Badge tone={isAdmin ? "brand" : "neutral"}>{roleLabel[org.role]}</Badge>
          </dd>
        </dl>
      </Card>
      <Card
        icon={<span className="cell-icon"><ShieldCheck size={16} /></span>}
        title="Security"
        description="Changing this requires a recent sign-in. To turn it on, that sign-in must itself use MFA."
      >
        <label className="check">
          <input
            type="checkbox"
            disabled={!isAdmin}
            checked={org.require_mfa}
            onChange={(e) =>
              void run(() => api("PATCH", base, { require_mfa: e.target.checked }), e.target.checked ? "MFA is now required" : "MFA is no longer required")
            }
          />
          <span>
            <strong>Require multi-factor authentication</strong>
            <br />
            <span className="muted">Members without MFA in their current session are asked to sign in again.</span>
          </span>
        </label>
        {!isAdmin && <p className="subtle">Only organization admins can change this.</p>}
      </Card>
      <Callout tone="info" icon={<KeyRound size={16} />} title="Secret values never stay here">
        SecretMesh stages proposed values in your cloud vault and promotes them on approval. Nothing is stored in this application.
      </Callout>
    </>
  );
}

// ---------- Members ----------

function Members({ data, base, run }: SectionProps) {
  const { org, members, invitations, tokens, now } = data;
  const isAdmin = org.role === "org_admin";
  const { confirm, dialog } = useConfirm();
  const [inviting, setInviting] = useState(false);
  const [creatingToken, setCreatingToken] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);

  return (
    <>
      {dialog}
      <Card
        flush
        icon={<span className="cell-icon"><Users size={16} /></span>}
        title="Members"
        description={`${members.length} ${members.length === 1 ? "person" : "people"} in ${org.name}`}
        actions={
          isAdmin && (
            <Button variant="primary" icon={<UserPlus size={15} />} onClick={() => setInviting(true)}>
              Invite
            </Button>
          )
        }
      >
        <div className="rows">
          {members.map((m) => (
            <div key={m.user_id} className="row-item">
              <Avatar email={m.email} />
              <div className="grow">
                <strong>{m.display_name || m.email}</strong>
                <small>
                  {m.email} · joined {ago(m.joined_at, now)}
                </small>
              </div>
              {isAdmin ? (
                <>
                  <select
                    className="select"
                    aria-label={`Role of ${m.email}`}
                    value={m.role}
                    onChange={(e) => void run(() => api("PATCH", `${base}/members/${m.user_id}`, { role: e.target.value }), "Role updated")}
                  >
                    <option value="member">Member</option>
                    <option value="org_admin">Admin</option>
                  </select>
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Remove ${m.email}`}
                    icon={<Trash2 size={14} />}
                    onClick={() =>
                      confirm({
                        title: `Remove ${m.email}?`,
                        body: `They lose access to ${org.name} immediately. Their audit history is kept.`,
                        action: "Remove member",
                        danger: true,
                        run: () => run(() => api("DELETE", `${base}/members/${m.user_id}`), "Member removed"),
                      })
                    }
                  />
                </>
              ) : (
                <Badge tone={m.role === "org_admin" ? "brand" : "neutral"}>{roleLabel[m.role]}</Badge>
              )}
            </div>
          ))}
        </div>
      </Card>

      {isAdmin && (
        <Card
          flush
          icon={<span className="cell-icon"><Mail size={16} /></span>}
          title="Pending invitations"
          description="Invited people join automatically the next time they sign in with this verified email address."
        >
          {invitations.length === 0 ? (
            <EmptyState icon={<Mail size={22} />} title="No pending invitations" />
          ) : (
            <div className="rows">
              {invitations.map((i) => (
                <div key={i.id} className="row-item">
                  <Avatar email={i.email} />
                  <div className="grow">
                    <strong>{i.email}</strong>
                    <small>
                      as {roleLabel[i.role]} · expires {ago(i.expires_at, now)}
                    </small>
                  </div>
                  <Button size="sm" onClick={() => void run(() => api("DELETE", `${base}/invitations/${i.id}`), "Invitation revoked")}>
                    Revoke
                  </Button>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {isAdmin && (
        <Card
          flush
          icon={<span className="cell-icon"><KeyRound size={16} /></span>}
          title="API tokens"
          description="Tokens act within this organization only, with the selected scopes, limited by your role."
          actions={
            <Button icon={<Plus size={15} />} onClick={() => setCreatingToken(true)}>
              New token
            </Button>
          }
        >
          {newToken && (
            <div style={{ padding: 16 }}>
              <Callout tone="success" title="Copy this token now. It will not be shown again.">
                <div className="secret-box" style={{ marginTop: 8 }}>
                  <code>{newToken}</code>
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <CopyButton value={newToken} />
                  <Button size="sm" onClick={() => setNewToken(null)}>
                    Done
                  </Button>
                </div>
              </Callout>
            </div>
          )}
          {tokens.length === 0 ? (
            <EmptyState icon={<KeyRound size={22} />} title="No API tokens">
              Create one for CI pipelines or scripts.
            </EmptyState>
          ) : (
            <div className="rows">
              {tokens.map((t) => (
                <div key={t.id} className="row-item">
                  <span className="cell-icon">
                    <KeyRound size={15} />
                  </span>
                  <div className="grow">
                    <strong>
                      {t.name} <code className="subtle">{t.display_prefix}…</code>
                    </strong>
                    <small>
                      expires {ago(t.expires_at, now)} · {t.last_used_at ? `last used ${ago(t.last_used_at, now)}` : "never used"}
                    </small>
                  </div>
                  <div className="chips">
                    {t.scopes.map((s) => (
                      <span key={s} className="chip mono">
                        {s}
                      </span>
                    ))}
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    icon={<Trash2 size={14} />}
                    aria-label={`Revoke ${t.name}`}
                    onClick={() =>
                      confirm({
                        title: `Revoke ${t.name}?`,
                        body: "Anything using this token stops working immediately.",
                        action: "Revoke token",
                        danger: true,
                        run: () => run(() => api("DELETE", `${base}/api-tokens/${t.id}`), "Token revoked"),
                      })
                    }
                  />
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      <Drawer open={inviting} onClose={() => setInviting(false)} icon={<UserPlus size={16} />} title="Invite a member" description="They join when they next sign in with this email.">
        <InviteForm
          onCancel={() => setInviting(false)}
          onInvite={async (email, role) => {
            const ok = await run(() => api("POST", `${base}/invitations`, { email, role }), `Invited ${email}`);
            if (ok) setInviting(false);
            return ok;
          }}
        />
      </Drawer>
      <Drawer open={creatingToken} onClose={() => setCreatingToken(false)} icon={<KeyRound size={16} />} title="New API token" description="The token is shown once after creation.">
        <TokenForm
          onCancel={() => setCreatingToken(false)}
          onCreate={async (name, scopes, days) => {
            const ok = await run(async () => {
              const res = await api<{ secret: string }>("POST", `${base}/api-tokens`, { name, scopes, expires_in_days: days });
              setNewToken(res.secret);
            }, "Token created");
            if (ok) setCreatingToken(false);
            return ok;
          }}
        />
      </Drawer>
    </>
  );
}

function InviteForm({ onInvite, onCancel }: { onInvite: (email: string, role: Role) => Promise<boolean>; onCancel: () => void }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    if (await onInvite(email.trim(), role)) setEmail("");
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <Field label="Email" htmlFor="inv-email">
        <input id="inv-email" className="input" type="email" required autoFocus placeholder="name@example.com" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Role" hint="Admins manage members, tokens and security settings. Access to secrets is granted separately under Access.">
        <Segmented<Role>
          options={[
            { id: "member", label: "Member" },
            { id: "org_admin", label: "Admin" },
          ]}
          value={role}
          onChange={setRole}
        />
      </Field>
      <FormActions busy={busy} label="Send invitation" onCancel={onCancel} />
    </form>
  );
}

function TokenForm({ onCreate, onCancel }: { onCreate: (name: string, scopes: Scope[], days: number) => Promise<boolean>; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<Scope[]>(["org:read"]);
  const [days, setDays] = useState(90);
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    await onCreate(name.trim(), scopes, days);
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <Field label="Name" htmlFor="tok-name">
        <input id="tok-name" className="input" required autoFocus maxLength={100} placeholder="e.g. ci-deploy" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Expires in">
        <Segmented<string>
          options={["30", "90", "180", "365"].map((d) => ({ id: d, label: `${d} days` }))}
          value={String(days)}
          onChange={(d) => setDays(Number(d))}
        />
      </Field>
      <Field label="Scopes">
        <div className="choice-grid">
          {SCOPES.map((s) => (
            <label key={s} className="check">
              <input type="checkbox" checked={scopes.includes(s)} onChange={(e) => setScopes(e.target.checked ? [...scopes, s] : scopes.filter((x) => x !== s))} />
              <code>{s}</code>
            </label>
          ))}
        </div>
      </Field>
      <FormActions busy={busy} label="Create token" disabled={scopes.length === 0} onCancel={onCancel} />
    </form>
  );
}

// ---------- Access ----------

function Access({ data, base, run }: SectionProps) {
  const [adding, setAdding] = useState(false);
  const { confirm, dialog } = useConfirm();
  if (!data.bindings) {
    return (
      <Card>
        <EmptyState icon={<ShieldCheck size={22} />} title="Admins only">
          Role bindings are managed by organization admins.
        </EmptyState>
      </Card>
    );
  }
  const byUser = new Map<string, RoleBinding[]>();
  for (const b of data.bindings) byUser.set(b.email, [...(byUser.get(b.email) ?? []), b]);

  return (
    <>
      {dialog}
      <Callout tone="info" icon={<ShieldCheck size={16} />}>
        Organization admins have no access to secrets until they bind themselves a role. Every change is audited.
      </Callout>
      <Card
        flush
        icon={<span className="cell-icon"><ShieldCheck size={16} /></span>}
        title="Role bindings"
        description="Who can do what, in which environments."
        actions={
          <Button variant="primary" icon={<Plus size={15} />} onClick={() => setAdding(true)}>
            Grant access
          </Button>
        }
      >
        {byUser.size === 0 ? (
          <EmptyState icon={<ShieldCheck size={22} />} title="No bindings yet" />
        ) : (
          <div className="rows">
            {[...byUser.entries()].map(([email, bs]) => (
              <div key={email} className="row-item" style={{ alignItems: "flex-start" }}>
                <Avatar email={email} />
                <div className="grow">
                  <strong>{email}</strong>
                  <div className="chips" style={{ marginTop: 6 }}>
                    {bs.map((b) => (
                      <span key={b.id} className="chip" title={roleHelp[b.role]}>
                        <Badge tone={roleTone[b.role]}>{b.role.replace("_", " ")}</Badge>
                        <span className="subtle">{envName(data, b.environment_id)}</span>
                        <button
                          className="icon-btn"
                          aria-label={`Remove ${b.role} from ${email}`}
                          onClick={() =>
                            confirm({
                              title: `Remove ${b.role.replace("_", " ")}?`,
                              body: `${email} loses this role in ${envName(data, b.environment_id).toLowerCase()}.`,
                              action: "Remove",
                              danger: true,
                              run: () => run(() => api("DELETE", `${base}/role-bindings/${b.id}`), "Access removed"),
                            })
                          }
                        >
                          <Trash2 size={12} />
                        </button>
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
      <Drawer open={adding} onClose={() => setAdding(false)} icon={<ShieldCheck size={16} />} title="Grant access" description="Bind a role to a member, everywhere or in one environment.">
        <BindingForm
          members={data.members}
          environments={data.environments}
          onCancel={() => setAdding(false)}
          onCreate={async (body) => {
            const ok = await run(() => api("POST", `${base}/role-bindings`, body), "Access granted");
            if (ok) setAdding(false);
            return ok;
          }}
        />
      </Drawer>
    </>
  );
}

function BindingForm({
  members,
  environments,
  onCreate,
  onCancel,
}: {
  members: Member[];
  environments: Environment[];
  onCreate: (body: Record<string, unknown>) => Promise<boolean>;
  onCancel: () => void;
}) {
  const [user, setUser] = useState(members[0]?.user_id ?? "");
  const [role, setRole] = useState<BindingRole>("developer");
  const [env, setEnv] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    await onCreate({ user_id: user, role, environment_id: env || undefined });
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <Field label="Member" htmlFor="b-user">
        <select id="b-user" className="select" required value={user} onChange={(e) => setUser(e.target.value)}>
          {members.map((m) => (
            <option key={m.user_id} value={m.user_id}>
              {m.email}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Role">
        <div className="choice-grid">
          {BINDING_ROLES.map((r) => (
            <button type="button" key={r} className="choice" aria-pressed={role === r} onClick={() => setRole(r)}>
              <span>
                <strong style={{ textTransform: "capitalize" }}>{r.replace("_", " ")}</strong>
                <small>{roleHelp[r]}</small>
              </span>
            </button>
          ))}
        </div>
      </Field>
      <Field label="Scope" htmlFor="b-env">
        <select id="b-env" className="select" value={env} onChange={(e) => setEnv(e.target.value)}>
          <option value="">All environments</option>
          {environments.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
      </Field>
      {role === "break_glass" && (
        <Callout tone="warning" title="Break-glass is powerful">
          Changes apply without prior approval. Every use alerts security admins and requires review afterwards.
        </Callout>
      )}
      <FormActions busy={busy} label="Grant access" onCancel={onCancel} />
    </form>
  );
}

// ---------- Environments ----------

function Environments({ data, base, run }: SectionProps) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<EnvironmentKind>("development");
  const counts = new Map<string, number>();
  for (const s of data.secrets) counts.set(s.environment_id, (counts.get(s.environment_id) ?? 0) + 1);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (await run(() => api("POST", `${base}/environments`, { name: name.trim(), kind }), `Created ${name.trim()}`)) setName("");
  }

  return (
    <>
      <Card flush icon={<span className="cell-icon"><Layers size={16} /></span>} title="Environments" description="Production changes need more approvals; policies are set per environment kind.">
        {data.environments.length === 0 ? (
          <EmptyState icon={<Layers size={22} />} title="No environments yet" />
        ) : (
          <div className="rows">
            {data.environments.map((e) => (
              <div key={e.id} className="row-item">
                <span className="cell-icon">
                  <Layers size={15} />
                </span>
                <div className="grow">
                  <strong>{e.name}</strong>
                  <small>
                    {counts.get(e.id) ?? 0} secrets · created {ago(e.created_at, data.now)}
                  </small>
                </div>
                <EnvBadge kind={e.kind} />
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card title="Add an environment">
        <form className="form" onSubmit={submit}>
          <div className="form-row">
            <Field label="Name" htmlFor="env-name" hint="Lowercase letters, digits and dashes.">
              <input id="env-name" className="input" required pattern="[a-z0-9][a-z0-9-]*" placeholder="e.g. prod" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Kind">
              <Segmented<EnvironmentKind>
                options={[
                  { id: "development", label: "Development" },
                  { id: "staging", label: "Staging" },
                  { id: "production", label: "Production" },
                ]}
                value={kind}
                onChange={setKind}
              />
            </Field>
          </div>
          <div>
            <Button type="submit" variant="primary" icon={<Plus size={15} />}>
              Add environment
            </Button>
          </div>
        </form>
      </Card>
    </>
  );
}

// ---------- Connections ----------

function Connections({ data, base, run }: SectionProps) {
  const [adding, setAdding] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);
  const secretCount = (id: string) => data.secrets.filter((s) => s.connection_id === id).length;

  async function sync(c: Connection) {
    setSyncing(c.id);
    let r: SyncResult | undefined;
    await run(
      async () => {
        r = await api<SyncResult>("POST", `${base}/connections/${c.id}/sync`);
      },
      `Synced ${c.name}`,
    );
    setSyncing(null);
    return r;
  }

  return (
    <>
      <Callout tone="info" icon={<Cloud size={16} />}>
        SecretMesh reaches each cloud by assuming a role you control. It never stores cloud credentials or secret values. See <code>docs/guides/aws.md</code> for the role template.
      </Callout>
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <Button variant="primary" icon={<Plus size={15} />} onClick={() => setAdding(true)}>
          Add AWS connection
        </Button>
      </div>
      {data.connections.length === 0 ? (
        <Card>
          <EmptyState icon={<Cloud size={22} />} title="No connections yet" action={<Button variant="primary" onClick={() => setAdding(true)}>Connect AWS</Button>}>
            Connect a cloud account to discover and govern its secrets.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid-2">
          {data.connections.map((c) => {
            const { external_id, ...config } = c.config;
            return (
              <Card
                key={c.id}
                icon={<span className="cell-icon"><Cloud size={16} /></span>}
                title={c.name}
                description={`${c.provider.toUpperCase()} · ${secretCount(c.id)} secrets`}
                actions={
                  c.capabilities?.discovery && (
                    <Button size="sm" loading={syncing === c.id} icon={<RefreshCw size={14} />} onClick={() => void sync(c)}>
                      Sync
                    </Button>
                  )
                }
              >
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {c.last_sync_error ? (
                    <Badge tone="danger" dot>
                      Sync failing
                    </Badge>
                  ) : c.last_synced_at ? (
                    <Badge tone="success" dot>
                      Healthy
                    </Badge>
                  ) : (
                    <Badge tone="warning" dot>
                      Never synced
                    </Badge>
                  )}
                  {c.capabilities?.native_rotation && <Badge tone="info">Native rotation</Badge>}
                  {c.capabilities?.versioning && <Badge outline>Versioned</Badge>}
                </div>
                <dl className="kv" style={{ gridTemplateColumns: "150px 1fr" }}>
                  {Object.entries(config).map(([k, v]) => (
                    <KV key={k} k={k.replace("_", " ")}>
                      <span className="mono">{v}</span>
                    </KV>
                  ))}
                  {external_id && (
                    <KV k="external ID">
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <span className="mono">{external_id}</span>
                        <CopyButton value={external_id} label="" />
                      </span>
                    </KV>
                  )}
                  <KV k="Default environment">{c.default_environment_id ? envName(data, c.default_environment_id) : <span className="subtle">None</span>}</KV>
                  {c.capabilities?.discovery && (
                    <KV k="Last sync">
                      {c.last_synced_at ? <span title={when(c.last_synced_at)}>{ago(c.last_synced_at, data.now)}</span> : <span className="subtle">Never</span>}
                    </KV>
                  )}
                </dl>
                {c.last_sync_error && (
                  <Callout tone="danger" title="Last sync failed">
                    {c.last_sync_error}
                  </Callout>
                )}
              </Card>
            );
          })}
        </div>
      )}
      <Drawer open={adding} onClose={() => setAdding(false)} icon={<Cloud size={16} />} title="Connect AWS" description="SecretMesh assumes an IAM role in your account using an ExternalId it generates.">
        <ConnectionForm
          environments={data.environments}
          onCancel={() => setAdding(false)}
          onCreate={async (body) => {
            const ok = await run(() => api("POST", `${base}/connections`, body), "Connection created", "Add the ExternalId to the role's trust policy, then click Sync.");
            if (ok) setAdding(false);
            return ok;
          }}
        />
      </Drawer>
    </>
  );
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt style={{ textTransform: "capitalize" }}>{k}</dt>
      <dd>{children}</dd>
    </>
  );
}

function ConnectionForm({
  environments,
  onCreate,
  onCancel,
}: {
  environments: Environment[];
  onCreate: (body: Record<string, unknown>) => Promise<boolean>;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [roleArn, setRoleArn] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [defaultEnv, setDefaultEnv] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    await onCreate({
      name: name.trim(),
      provider: "aws",
      config: { role_arn: roleArn.trim(), region: region.trim() },
      default_environment_id: defaultEnv || undefined,
    });
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <Field label="Name" htmlFor="c-name" hint="Lowercase letters, digits and dashes.">
        <input id="c-name" className="input" required autoFocus pattern="[a-z0-9][a-z0-9-]*" placeholder="e.g. aws-prod" value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Field label="Role ARN" htmlFor="c-arn">
        <input id="c-arn" className="input mono" required placeholder="arn:aws:iam::123456789012:role/secretmesh-connector" value={roleArn} onChange={(e) => setRoleArn(e.target.value)} />
      </Field>
      <Field label="Region" htmlFor="c-region">
        <input id="c-region" className="input" required value={region} onChange={(e) => setRegion(e.target.value)} />
      </Field>
      <Field label="Environment for untagged secrets" htmlFor="c-env" hint="Discovered secrets without a secretmesh:environment tag land here.">
        <select id="c-env" className="select" value={defaultEnv} onChange={(e) => setDefaultEnv(e.target.value)}>
          <option value="">None (skip them)</option>
          {environments.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
      </Field>
      <Callout tone="info" title="Next steps">
        After creating the connection, copy its ExternalId into the role&apos;s trust policy, then click Sync.
      </Callout>
      <FormActions busy={busy} label="Create connection" onCancel={onCancel} />
    </form>
  );
}

// ---------- Notifications ----------

function Notifications({ data, base, run }: SectionProps) {
  const [adding, setAdding] = useState(false);
  const { confirm, dialog } = useConfirm();
  return (
    <>
      {dialog}
      <Card
        flush
        icon={<span className="cell-icon"><Bell size={16} /></span>}
        title="Channels"
        description="Approval requests, outcomes, break-glass alerts, rotation reminders, escalations and failures. Email goes to the people each event concerns. Notifications never contain secret values."
        actions={
          <Button variant="primary" icon={<Plus size={15} />} onClick={() => setAdding(true)}>
            Add channel
          </Button>
        }
      >
        {data.channels.length === 0 ? (
          <EmptyState icon={<Bell size={22} />} title="No channels yet">
            {data.emailAvailable ? "Add email to notify approvers and owners." : "No SMTP server is configured; add a Slack channel."}
          </EmptyState>
        ) : (
          <div className="rows">
            {data.channels.map((c) => (
              <div key={c.id} className="row-item">
                <span className="cell-icon">{c.kind === "email" ? <Mail size={15} /> : <MessageSquare size={15} />}</span>
                <div className="grow">
                  <strong>{c.name}</strong>
                  <small>
                    {c.kind === "email"
                      ? "Email to the people each event concerns"
                      : `Slack webhook from ${data.secrets.find((s) => s.id === c.webhook_secret_id)?.name ?? "a secret not visible to you"}`}
                  </small>
                </div>
                <Badge tone={c.enabled ? "success" : "neutral"} dot>
                  {c.enabled ? "Active" : "Disabled"}
                </Badge>
                <Button size="sm" icon={<Send size={14} />} onClick={() => void run(() => api("POST", `${base}/notification-channels/${c.id}/test`), "Test notification queued")}>
                  Test
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<Trash2 size={14} />}
                  aria-label={`Remove ${c.name}`}
                  onClick={() =>
                    confirm({
                      title: `Remove ${c.name}?`,
                      body: "Notifications stop going to this channel.",
                      action: "Remove channel",
                      danger: true,
                      run: () => run(() => api("DELETE", `${base}/notification-channels/${c.id}`), "Channel removed"),
                    })
                  }
                />
              </div>
            ))}
          </div>
        )}
      </Card>

      {data.deliveries && (
        <Card flush title="Recent deliveries" description="Delivery attempts are retried with backoff.">
          {data.deliveries.length === 0 ? (
            <EmptyState icon={<Send size={22} />} title="Nothing sent yet" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Subject</th>
                  <th>Channel</th>
                  <th>Status</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {data.deliveries.map((d) => (
                  <tr key={d.notification_id + d.channel}>
                    <td>
                      <div className="cell-main">
                        <strong>{d.subject}</strong>
                        <span className="subtle mono">{d.event}</span>
                      </div>
                    </td>
                    <td>{d.channel}</td>
                    <td>
                      <Badge tone={d.status === "sent" ? "success" : d.status === "failed" ? "danger" : "warning"} dot title={d.last_error}>
                        {d.status}
                        {d.attempts > 1 && ` · ${d.attempts} tries`}
                      </Badge>
                      {d.last_error && <div className="subtle" style={{ fontSize: 12, marginTop: 4 }}>{d.last_error}</div>}
                    </td>
                    <td className="muted" title={when(d.created_at)}>
                      {ago(d.created_at, data.now)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      <Drawer open={adding} onClose={() => setAdding(false)} icon={<Bell size={16} />} title="Add a channel">
        <ChannelForm
          emailAvailable={data.emailAvailable}
          secrets={data.secrets}
          onCancel={() => setAdding(false)}
          onCreate={async (body) => {
            const ok = await run(() => api("POST", `${base}/notification-channels`, body), "Channel added");
            if (ok) setAdding(false);
            return ok;
          }}
        />
      </Drawer>
    </>
  );
}

function ChannelForm({
  emailAvailable,
  secrets,
  onCreate,
  onCancel,
}: {
  emailAvailable: boolean;
  secrets: Secret[];
  onCreate: (body: Record<string, unknown>) => Promise<boolean>;
  onCancel: () => void;
}) {
  const [kind, setKind] = useState<"email" | "slack">(emailAvailable ? "email" : "slack");
  const [name, setName] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    await onCreate({ kind, name: name.trim(), webhook_secret_id: kind === "slack" ? secret : undefined });
    setBusy(false);
  }
  return (
    <form className="form" onSubmit={submit}>
      <div className="choice-grid">
        <button type="button" className="choice" aria-pressed={kind === "email"} disabled={!emailAvailable} onClick={() => setKind("email")}>
          <Mail size={18} />
          <span>
            <strong>Email</strong>
            <small>{emailAvailable ? "Sent to approvers, requesters and owners" : "No SMTP server configured"}</small>
          </span>
        </button>
        <button type="button" className="choice" aria-pressed={kind === "slack"} onClick={() => setKind("slack")}>
          <MessageSquare size={18} />
          <span>
            <strong>Slack</strong>
            <small>Posts to an incoming webhook</small>
          </span>
        </button>
      </div>
      <Field label="Name" htmlFor="ch-name">
        <input id="ch-name" className="input" required maxLength={100} placeholder={kind === "email" ? "e.g. Email" : "e.g. #security-alerts"} value={name} onChange={(e) => setName(e.target.value)} />
      </Field>
      {kind === "slack" && (
        <Field label="Webhook secret" htmlFor="ch-secret" hint="Store the Slack webhook URL as a secret in your vault. SecretMesh reads it only when sending and never stores it.">
          <select id="ch-secret" className="select" required value={secret} onChange={(e) => setSecret(e.target.value)}>
            <option value="">Choose a secret…</option>
            {secrets.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </Field>
      )}
      <FormActions busy={busy} label="Add channel" onCancel={onCancel} />
    </form>
  );
}

function FormActions({ busy, label, disabled, onCancel }: { busy: boolean; label: string; disabled?: boolean; onCancel: () => void }) {
  return (
    <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
      <Button type="button" onClick={onCancel}>
        Cancel
      </Button>
      <Button type="submit" variant="primary" loading={busy} disabled={disabled}>
        {label}
      </Button>
    </div>
  );
}
