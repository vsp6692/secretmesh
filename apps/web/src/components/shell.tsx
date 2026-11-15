"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Bell,
  ChevronsUpDown,
  CornerDownLeft,
  FileClock,
  GitPullRequestArrow,
  KeyRound,
  LayoutDashboard,
  Loader2,
  LogOut,
  Moon,
  Plus,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  ShieldAlert,
  Sun,
} from "lucide-react";
import { api, ApiError, stepUpURL, type ChangeRequest, type Me, type Organization, type Secret } from "@/lib/api";
import { OrgCtx, type OrgContext } from "@/components/org";
import { Avatar, Badge, Button, ToastProvider } from "@/components/ui";

type Blocked = "signed-out" | "not-found" | "mfa" | { error: string };

export function AppShell({ orgId, children }: { orgId: string; children: ReactNode }) {
  return (
    <ToastProvider>
      <Shell orgId={orgId}>{children}</Shell>
    </ToastProvider>
  );
}

function Shell({ orgId, children }: { orgId: string; children: ReactNode }) {
  const base = `/orgs/${encodeURIComponent(orgId)}`;
  const href = `/orgs/${orgId}`;
  const pathname = usePathname();
  const [state, setState] = useState<{ me: Me; org: Organization } | null>(null);
  const [blocked, setBlocked] = useState<Blocked | null>(null);
  const [counts, setCounts] = useState({ review: 0, overdue: 0 });
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    Promise.all([api<Me>("GET", "/me"), api<Organization>("GET", base)]).then(
      ([me, org]) => setState({ me, org }),
      (e) => {
        if (e instanceof ApiError && e.status === 401) setBlocked("signed-out");
        else if (e instanceof ApiError && e.code === "not_found") setBlocked("not-found");
        else if (e instanceof ApiError && e.code === "mfa_required") setBlocked("mfa");
        else setBlocked({ error: (e as Error).message });
      },
    );
  }, [base]);

  const refreshCounts = useCallback(() => {
    if (!state) return;
    const now = Date.now();
    Promise.all([
      api<{ change_requests: ChangeRequest[] }>("GET", `${base}/change-requests?status=pending`).catch(() => ({ change_requests: [] })),
      api<{ secrets: Secret[] }>("GET", `${base}/secrets`).catch(() => ({ secrets: [] })),
    ]).then(([crs, secs]) =>
      setCounts({
        review: crs.change_requests.filter((c) => c.requested_by !== state.me.user.id && !c.decisions.some((d) => d.approver_id === state.me.user.id)).length,
        overdue: secs.secrets.filter((s) => s.rotation_enabled && s.next_rotation_at && Date.parse(s.next_rotation_at) < now).length,
      }),
    );
  }, [base, state]);

  useEffect(() => {
    refreshCounts();
  }, [refreshCounts, pathname]);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  const ctx: OrgContext | null = useMemo(
    () => (state ? { orgId, base, href, org: state.org, me: state.me, counts, refreshCounts } : null),
    [state, orgId, base, href, counts, refreshCounts],
  );

  if (blocked) return <BlockedScreen blocked={blocked} path={pathname} />;
  if (!ctx) {
    return (
      <div className="center-screen">
        <Loader2 className="spin" size={22} color="var(--text-subtle)" />
      </div>
    );
  }

  const nav = [
    { href: href, label: "Dashboard", icon: <LayoutDashboard size={17} />, exact: true },
    { href: `${href}/secrets`, label: "Secrets", icon: <KeyRound size={17} /> },
    { href: `${href}/changes`, label: "Approvals", icon: <GitPullRequestArrow size={17} />, count: counts.review },
    { href: `${href}/rotation`, label: "Rotation", icon: <RefreshCw size={17} />, count: counts.overdue, warn: true },
    { href: `${href}/audit`, label: "Audit log", icon: <FileClock size={17} /> },
  ];

  return (
    <OrgCtx.Provider value={ctx}>
      <div className="shell">
        <aside className="sidebar">
          <Link href="/" className="brand">
            <span className="brand-mark">
              <ShieldCheck size={17} />
            </span>
            SecretMesh
          </Link>
          <OrgSwitcher me={ctx.me} org={ctx.org} />
          <span className="nav-label">Workspace</span>
          {nav.map((n) => {
            const current = n.exact ? pathname === n.href : pathname.startsWith(n.href);
            return (
              <Link key={n.href} href={n.href} className="nav-item" aria-current={current ? "page" : undefined}>
                {n.icon}
                {n.label}
                {!!n.count && <span className={n.warn ? "nav-count warn" : "nav-count"}>{n.count}</span>}
              </Link>
            );
          })}
          <span className="nav-label">Administration</span>
          <Link href={`${href}/settings`} className="nav-item" aria-current={pathname.startsWith(`${href}/settings`) ? "page" : undefined}>
            <Settings size={17} />
            Settings
          </Link>
          <div className="sidebar-foot">
            <div className="user-card">
              <Avatar email={ctx.me.user.email} />
              <div className="who">
                <strong>{ctx.me.user.display_name || ctx.me.user.email}</strong>
                <small>{ctx.me.session.mfa ? "MFA session" : "Signed in without MFA"}</small>
              </div>
              <form method="post" action="/auth/logout">
                <button className="icon-btn" title="Sign out" aria-label="Sign out" type="submit">
                  <LogOut size={16} />
                </button>
              </form>
            </div>
          </div>
        </aside>

        <div className="main">
          <div className="topbar">
            <button className="search-trigger" onClick={() => setPalette(true)}>
              <Search size={15} />
              Search secrets, pages and actions…
              <span className="kbd">⌘K</span>
            </button>
            <div className="topbar-actions">
              {!ctx.me.session.mfa && (
                <a href={stepUpURL(pathname)} title="Production changes and reveals need MFA">
                  <Badge tone="warning" dot>
                    No MFA
                  </Badge>
                </a>
              )}
              <Link href={`${href}/changes`} className="icon-btn" title="Approvals waiting for you" aria-label="Approvals">
                <span style={{ position: "relative", display: "inline-grid" }}>
                  <Bell size={17} />
                  {counts.review > 0 && (
                    <span style={{ position: "absolute", top: -3, right: -3, width: 8, height: 8, borderRadius: 99, background: "var(--danger)" }} />
                  )}
                </span>
              </Link>
              <ThemeToggle />
            </div>
          </div>
          <main className="content">{children}</main>
        </div>
      </div>
      {palette && <CommandPalette onClose={() => setPalette(false)} />}
    </OrgCtx.Provider>
  );
}

function OrgSwitcher({ me, org }: { me: Me; org: Organization }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="org-switch">
      <button onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="org-avatar">{org.name[0]?.toUpperCase()}</span>
        <span style={{ flex: 1, minWidth: 0 }}>
          {org.name}
          <small>{org.role === "org_admin" ? "Admin" : "Member"}</small>
        </span>
        <ChevronsUpDown size={15} />
      </button>
      {open && (
        <div
          className="card"
          style={{ position: "absolute", left: 0, right: 0, top: "calc(100% + 6px)", zIndex: 30, padding: 6, color: "var(--text)" }}
        >
          {me.organizations.map((o) => (
            <Link key={o.id} href={`/orgs/${o.id}`} className="palette-item" onClick={() => setOpen(false)} aria-selected={o.id === org.id}>
              <span className="org-avatar" style={{ background: "var(--brand)" }}>
                {o.name[0]?.toUpperCase()}
              </span>
              {o.name}
              <small>{o.slug}</small>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

function ThemeToggle() {
  useEffect(() => {
    const saved = localStorage.getItem("sm-theme");
    if (saved === "light" || saved === "dark") document.documentElement.dataset.theme = saved;
  }, []);
  return (
    <button
      className="icon-btn"
      title="Toggle theme"
      aria-label="Toggle theme"
      onClick={() => {
        const el = document.documentElement;
        const dark = el.dataset.theme ? el.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
        el.dataset.theme = dark ? "light" : "dark";
        localStorage.setItem("sm-theme", el.dataset.theme);
      }}
    >
      <Sun size={17} className="theme-sun" />
      <Moon size={17} className="theme-moon" />
    </button>
  );
}

interface PaletteItem {
  group: string;
  label: string;
  hint?: string;
  icon: ReactNode;
  href: string;
}

function CommandPalette({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const pathname = usePathname();
  const orgHref = pathname.split("/").slice(0, 3).join("/");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    input.current?.focus();
    api<{ secrets: Secret[] }>("GET", `${orgHref}/secrets`).then(
      (r) => setSecrets(r.secrets),
      () => setSecrets([]),
    );
  }, [orgHref]);

  const items: PaletteItem[] = useMemo(() => {
    const all: PaletteItem[] = [
      { group: "Actions", label: "Propose a new secret", icon: <Plus size={16} />, href: `${orgHref}/secrets?new=1` },
      { group: "Actions", label: "Review approvals", icon: <GitPullRequestArrow size={16} />, href: `${orgHref}/changes` },
      { group: "Actions", label: "Verify audit log integrity", icon: <ShieldAlert size={16} />, href: `${orgHref}/audit?verify=1` },
      { group: "Pages", label: "Dashboard", icon: <LayoutDashboard size={16} />, href: orgHref },
      { group: "Pages", label: "Secrets", icon: <KeyRound size={16} />, href: `${orgHref}/secrets` },
      { group: "Pages", label: "Rotation", icon: <RefreshCw size={16} />, href: `${orgHref}/rotation` },
      { group: "Pages", label: "Audit log", icon: <FileClock size={16} />, href: `${orgHref}/audit` },
      { group: "Pages", label: "Settings", icon: <Settings size={16} />, href: `${orgHref}/settings` },
      ...secrets.map((s) => ({
        group: "Secrets",
        label: s.name,
        hint: s.environment_kind,
        icon: <KeyRound size={16} />,
        href: `${orgHref}/secrets/${s.id}`,
      })),
    ];
    const needle = q.trim().toLowerCase();
    return (needle ? all.filter((i) => i.label.toLowerCase().includes(needle)) : all).slice(0, 40);
  }, [q, secrets, orgHref]);

  const go = (i: PaletteItem | undefined) => {
    if (!i) return;
    onClose();
    router.push(i.href);
  };

  let lastGroup = "";
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="dialog palette" role="dialog" aria-modal="true" aria-label="Command palette">
        <div className="palette-input">
          <Search size={17} />
          <input
            ref={input}
            value={q}
            placeholder="Type a command or search secrets…"
            onChange={(e) => {
              setQ(e.target.value);
              setSel(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "Escape") onClose();
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setSel((s) => Math.min(s + 1, items.length - 1));
              }
              if (e.key === "ArrowUp") {
                e.preventDefault();
                setSel((s) => Math.max(s - 1, 0));
              }
              if (e.key === "Enter") go(items[sel]);
            }}
          />
          <span className="kbd">esc</span>
        </div>
        <div className="palette-list" role="listbox">
          {items.length === 0 && <p className="subtle" style={{ padding: 16 }}>No results for “{q}”.</p>}
          {items.map((i, idx) => {
            const header = i.group !== lastGroup ? <div className="palette-group">{i.group}</div> : null;
            lastGroup = i.group;
            return (
              <div key={i.group + i.href}>
                {header}
                <button className="palette-item" role="option" aria-selected={idx === sel} onMouseEnter={() => setSel(idx)} onClick={() => go(i)}>
                  {i.icon}
                  {i.label}
                  {i.hint ? <small>{i.hint}</small> : idx === sel ? <small><CornerDownLeft size={13} /></small> : null}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}

function BlockedScreen({ blocked, path }: { blocked: Blocked; path: string }) {
  return (
    <div className="center-screen">
      <div className="card" style={{ width: "min(440px, calc(100vw - 32px))" }}>
        <div className="card-body" style={{ alignItems: "center", textAlign: "center", padding: 32 }}>
          <span className="brand-mark" style={{ width: 44, height: 44, borderRadius: 13 }}>
            <ShieldCheck size={22} />
          </span>
          {blocked === "signed-out" && (
            <>
              <h2>Sign in to continue</h2>
              <p className="muted">Your session has ended. Sign in with your organization&apos;s identity provider.</p>
              <a className="btn primary lg" href={`/auth/login?return_to=${encodeURIComponent(path)}`}>
                Sign in
              </a>
            </>
          )}
          {blocked === "not-found" && (
            <>
              <h2>Organization not found</h2>
              <p className="muted">It doesn&apos;t exist or you are not a member.</p>
              <Link className="btn" href="/">
                Back to your organizations
              </Link>
            </>
          )}
          {blocked === "mfa" && (
            <>
              <h2>Multi-factor authentication required</h2>
              <p className="muted">This organization requires MFA. Sign in again and complete the second factor.</p>
              <a className="btn primary lg" href={stepUpURL(path)}>
                Sign in with MFA
              </a>
            </>
          )}
          {typeof blocked === "object" && (
            <>
              <h2>Something went wrong</h2>
              <p className="muted">{blocked.error}</p>
              <Button onClick={() => location.reload()}>Try again</Button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
