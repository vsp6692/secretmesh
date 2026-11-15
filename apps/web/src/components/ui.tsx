// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

"use client";

import Link from "next/link";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type ReactNode,
} from "react";
import { AlertTriangle, CheckCircle2, ChevronRight, Copy, Check, Info, Loader2, X, XCircle } from "lucide-react";

// ---------- Buttons ----------

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
  icon?: ReactNode;
  loading?: boolean;
};

export function Button({ variant = "secondary", size = "md", icon, loading, children, className, disabled, ...rest }: ButtonProps) {
  const cls = ["btn", variant !== "secondary" && variant, size !== "md" && size, className].filter(Boolean).join(" ");
  return (
    <button type="button" className={cls} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 size={15} className="spin" /> : icon}
      {children}
    </button>
  );
}

export function ButtonLink({ href, variant = "secondary", icon, children }: { href: string; variant?: "primary" | "secondary" | "ghost"; icon?: ReactNode; children: ReactNode }) {
  return (
    <Link href={href} className={["btn", variant !== "secondary" && variant].filter(Boolean).join(" ")}>
      {icon}
      {children}
    </Link>
  );
}

// ---------- Badges ----------

export type Tone = "neutral" | "brand" | "success" | "warning" | "danger" | "info";

export function Badge({ tone = "neutral", dot, pulse, outline, children, title }: { tone?: Tone; dot?: boolean; pulse?: boolean; outline?: boolean; children: ReactNode; title?: string }) {
  return (
    <span className={["badge", tone !== "neutral" && tone, pulse && "pulse", outline && "outline"].filter(Boolean).join(" ")} title={title}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

const statusTone: Record<string, Tone> = {
  pending: "warning",
  approved: "info",
  executing: "brand",
  succeeded: "success",
  failed: "danger",
  rejected: "danger",
  cancelled: "neutral",
  expired: "neutral",
  scheduled: "info",
  rotating: "brand",
  verifying: "brand",
  sent: "success",
};

export function StatusBadge({ status }: { status: string }) {
  const live = ["executing", "rotating", "verifying", "pending"].includes(status);
  return (
    <Badge tone={statusTone[status] ?? "neutral"} dot pulse={live}>
      {status[0].toUpperCase() + status.slice(1)}
    </Badge>
  );
}

const envTone: Record<string, Tone> = { production: "danger", staging: "warning", development: "info" };

export function EnvBadge({ kind, name }: { kind: string; name?: string }) {
  return (
    <Badge tone={envTone[kind] ?? "neutral"} outline>
      {name ?? kind}
    </Badge>
  );
}

const classTone: Record<string, Tone> = { restricted: "danger", confidential: "brand", internal: "neutral" };

export function ClassBadge({ value }: { value: string }) {
  return <Badge tone={classTone[value] ?? "neutral"}>{value}</Badge>;
}

// ---------- Layout ----------

export function PageHeader({
  title,
  description,
  actions,
  crumbs,
  badges,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  crumbs?: { href: string; label: string }[];
  badges?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div style={{ minWidth: 0 }}>
        {crumbs && (
          <nav className="crumbs" aria-label="Breadcrumb">
            {crumbs.map((c) => (
              <span key={c.href} style={{ display: "contents" }}>
                <Link href={c.href}>{c.label}</Link>
                <ChevronRight size={13} />
              </span>
            ))}
          </nav>
        )}
        <div className="title-row">
          <h1>{title}</h1>
          {badges}
        </div>
        {description && <p>{description}</p>}
      </div>
      {actions && <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>{actions}</div>}
    </header>
  );
}

export function Card({
  title,
  description,
  actions,
  icon,
  flush,
  children,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  icon?: ReactNode;
  flush?: boolean;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section className={["card", className].filter(Boolean).join(" ")}>
      {(title || actions) && (
        <div className="card-head">
          {icon}
          <div style={{ minWidth: 0 }}>
            {title && <h2>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      <div className={flush ? "card-body flush" : "card-body"}>{children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  hint,
  icon,
  tone,
  href,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon: ReactNode;
  tone?: Tone;
  href?: string;
}) {
  const cls = ["card", "stat", tone && `tone-${tone}`].filter(Boolean).join(" ");
  const inner = (
    <>
      <span className="label">
        <span className="stat-icon">{icon}</span>
        {label}
      </span>
      <span className="value">{value}</span>
      {hint && <span className="hint">{hint}</span>}
    </>
  );
  return href ? (
    <Link href={href} className={cls}>
      {inner}
    </Link>
  ) : (
    <div className={cls}>{inner}</div>
  );
}

export function EmptyState({ icon, title, children, action }: { icon: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon">{icon}</span>
      <h2>{title}</h2>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Skeleton({ width = "100%", height = 14 }: { width?: number | string; height?: number }) {
  return <span className="skeleton" style={{ display: "block", width, height }} />;
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="rows">
      {Array.from({ length: rows }, (_, i) => (
        <div className="row-item" key={i}>
          <Skeleton width={32} height={32} />
          <div className="grow" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <Skeleton width={`${50 + ((i * 17) % 40)}%`} />
            <Skeleton width="30%" height={10} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function Callout({ tone = "info", icon, title, children }: { tone?: "info" | "warning" | "danger" | "success"; icon?: ReactNode; title?: ReactNode; children?: ReactNode }) {
  const Default = tone === "danger" ? XCircle : tone === "warning" ? AlertTriangle : tone === "success" ? CheckCircle2 : Info;
  return (
    <div className={`callout ${tone}`}>
      {icon ?? <Default size={17} />}
      <div style={{ minWidth: 0 }}>
        {title && <strong style={{ display: "block", fontWeight: 600 }}>{title}</strong>}
        {children && <div className="muted" style={{ fontSize: 13 }}>{children}</div>}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; icon?: ReactNode; count?: number }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" type="button" aria-selected={t.id === value} onClick={() => onChange(t.id)}>
          {t.icon}
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ options, value, onChange }: { options: { id: T; label: string; icon?: ReactNode }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="seg">
      {options.map((o) => (
        <button key={o.id} type="button" aria-pressed={o.id === value} onClick={() => onChange(o.id)}>
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="field">
      <label htmlFor={htmlFor}>{label}</label>
      {children}
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

const palette = ["#5b4cf0", "#1f72d6", "#12976a", "#c2410c", "#be185d", "#0e7490", "#7c3aed", "#b45309"];

export function Avatar({ email, size }: { email: string; size?: "sm" }) {
  let h = 0;
  for (const c of email) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const initials = email
    .split("@")[0]
    .split(/[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase())
    .join("");
  return (
    <span className={size === "sm" ? "avatar sm" : "avatar"} style={{ background: palette[h % palette.length] }} title={email}>
      {initials || "?"}
    </span>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      size="sm"
      variant="ghost"
      icon={done ? <Check size={14} /> : <Copy size={14} />}
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {done ? "Copied" : label}
    </Button>
  );
}

// ---------- Overlays ----------

function useEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
}

export function Drawer({
  open,
  onClose,
  title,
  description,
  icon,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(open, onClose);
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="drawer-head">
          {icon && <span className="cell-icon">{icon}</span>}
          <div style={{ flex: 1 }}>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={17} />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </aside>
    </>
  );
}

export function Dialog({
  open,
  onClose,
  title,
  description,
  icon,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(open, onClose);
  if (!open) return null;
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="dialog" role="dialog" aria-modal="true">
        <div className="drawer-head">
          {icon && <span className="cell-icon">{icon}</span>}
          <div style={{ flex: 1 }}>
            <h2>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={17} />
          </button>
        </div>
        {children && <div className="drawer-body">{children}</div>}
        {footer && <div className="drawer-foot">{footer}</div>}
      </div>
    </>
  );
}

/** Asks for confirmation before running a (possibly async) action. */
export function useConfirm() {
  const [state, setState] = useState<{ title: string; body?: ReactNode; action: string; danger?: boolean; run: () => Promise<unknown> | void } | null>(null);
  const [busy, setBusy] = useState(false);
  const close = useCallback(() => setState(null), []);
  const dialog = (
    <Dialog
      open={!!state}
      onClose={close}
      title={state?.title}
      description={state?.body}
      footer={
        <>
          <Button onClick={close}>Cancel</Button>
          <Button
            variant={state?.danger ? "danger" : "primary"}
            loading={busy}
            onClick={async () => {
              if (!state) return;
              setBusy(true);
              try {
                await state.run();
              } finally {
                setBusy(false);
                setState(null);
              }
            }}
          >
            {state?.action}
          </Button>
        </>
      }
    />
  );
  return { confirm: setState, dialog };
}

// ---------- Toasts ----------

type Toast = { id: number; tone: "success" | "error" | "info"; title: string; body?: ReactNode; action?: ReactNode };

const ToastContext = createContext<(t: Omit<Toast, "id">) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);
  const push = useCallback((t: Omit<Toast, "id">) => {
    const id = next.current++;
    setToasts((ts) => [...ts.slice(-3), { ...t, id }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), t.tone === "error" ? 8000 : 4500);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} role={t.tone === "error" ? "alert" : "status"}>
            <span className="t-icon">
              {t.tone === "success" ? <CheckCircle2 size={18} /> : t.tone === "error" ? <XCircle size={18} /> : <Info size={18} />}
            </span>
            <div className="grow">
              <strong>{t.title}</strong>
              {t.body && <p>{t.body}</p>}
              {t.action && <div style={{ marginTop: 8 }}>{t.action}</div>}
            </div>
            <button className="icon-btn" style={{ width: 24, height: 24 }} aria-label="Dismiss" onClick={() => setToasts((ts) => ts.filter((x) => x.id !== t.id))}>
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}

// ---------- Time ----------

/** Relative time; now is passed in so rendering stays pure. */
export function ago(t: string | undefined, now: number): string {
  if (!t) return "—";
  const d = (Date.parse(t) - now) / 1000;
  const abs = Math.abs(d);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60) return rtf.format(Math.round(d), "second");
  if (abs < 3600) return rtf.format(Math.round(d / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(d / 3600), "hour");
  if (abs < 86400 * 30) return rtf.format(Math.round(d / 86400), "day");
  return new Date(t).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function when(t?: string): string {
  return t ? new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
}
