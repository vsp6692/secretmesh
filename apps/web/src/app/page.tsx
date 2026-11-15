"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, Building2, CheckCircle2, FileClock, KeyRound, LogOut, RefreshCw, ShieldCheck, Users } from "lucide-react";
import { getMe, type Me } from "@/lib/api";
import { Avatar, Badge, Button, Callout, Skeleton } from "@/components/ui";

type State = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "signed-in"; me: Me };

const points = [
  { icon: <KeyRound size={18} />, text: "Values stay in your cloud vault. Proposed changes are staged there and promoted only after approval." },
  { icon: <Users size={18} />, text: "Four-eyes approval with MFA, scoped roles per environment, and audited break-glass." },
  { icon: <RefreshCw size={18} />, text: "Rotation schedules with reminders and escalation, or native provider rotation." },
  { icon: <FileClock size={18} />, text: "Hash-chained, signed audit log you can verify at any time." },
];

export default function Home() {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    getMe()
      .then((me) => setState(me ? { kind: "signed-in", me } : { kind: "signed-out" }))
      .catch((err: Error) => setState({ kind: "error", message: err.message }));
  }, []);

  return (
    <main className="landing">
      <section className="landing-art">
        <div className="brand" style={{ color: "#fff", padding: 0 }}>
          <span className="brand-mark">
            <ShieldCheck size={17} />
          </span>
          SecretMesh
        </div>
        <div>
          <h1>Govern every secret across every cloud — without holding a single value.</h1>
          <p>Discover, approve, rotate and audit secrets in AWS and beyond. Self-hosted first, built for teams that take secrets seriously.</p>
          <div className="landing-points">
            {points.map((p, i) => (
              <div key={i}>
                {p.icon}
                <span>{p.text}</span>
              </div>
            ))}
          </div>
        </div>
        <small style={{ color: "#7d84a8" }}>Zero secret persistence · OPA policies · Hash-chained audit</small>
      </section>

      <section className="landing-panel">
        <div className="landing-card">
          {state.kind === "loading" && (
            <>
              <Skeleton width="60%" height={28} />
              <Skeleton height={64} />
              <Skeleton height={64} />
            </>
          )}

          {state.kind === "error" && (
            <Callout tone="danger" title="Can't reach SecretMesh">
              {state.message}
              <div style={{ marginTop: 10 }}>
                <Button size="sm" onClick={() => location.reload()}>
                  Try again
                </Button>
              </div>
            </Callout>
          )}

          {state.kind === "signed-out" && (
            <>
              <div>
                <h2 style={{ fontSize: 26 }}>Welcome back</h2>
                <p className="muted" style={{ marginTop: 6 }}>
                  Sign in with your organization&apos;s identity provider.
                </p>
              </div>
              <a className="btn primary lg" href="/auth/login" style={{ justifyContent: "center" }}>
                Continue with SSO <ArrowRight size={16} />
              </a>
              <p className="subtle" style={{ fontSize: 12.5 }}>
                <CheckCircle2 size={13} style={{ verticalAlign: -2 }} /> Your organization may require multi-factor authentication.
              </p>
            </>
          )}

          {state.kind === "signed-in" && (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <Avatar email={state.me.user.email} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h2 style={{ fontSize: 20 }}>Hi{state.me.user.display_name ? `, ${state.me.user.display_name.split(" ")[0]}` : ""}</h2>
                  <p className="muted" style={{ fontSize: 13 }}>
                    {state.me.user.email}
                    {!state.me.session.mfa && (
                      <>
                        {" "}
                        <Badge tone="warning">No MFA</Badge>
                      </>
                    )}
                  </p>
                </div>
                <form method="post" action="/auth/logout">
                  <Button type="submit" size="sm" variant="ghost" icon={<LogOut size={14} />}>
                    Sign out
                  </Button>
                </form>
              </div>
              <div>
                <h3 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: "0.06em" }} className="subtle">
                  Your organizations
                </h3>
              </div>
              {state.me.organizations.length === 0 ? (
                <Callout tone="info" icon={<Building2 size={16} />} title="No organizations yet">
                  Ask an organization admin to invite this email address, then sign in again.
                </Callout>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {state.me.organizations.map((org) => (
                    <Link key={org.id} href={`/orgs/${org.id}`} className="org-tile">
                      <span className="brand-mark" style={{ background: "var(--brand-soft)", color: "var(--brand)" }}>
                        {org.name.slice(0, 1).toUpperCase()}
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <strong>{org.name}</strong>
                        <div className="subtle" style={{ fontSize: 12.5 }}>
                          {org.slug}
                          {org.require_mfa && " · MFA required"}
                        </div>
                      </div>
                      <Badge tone={org.role === "org_admin" ? "brand" : "neutral"}>{org.role === "org_admin" ? "Admin" : "Member"}</Badge>
                      <ArrowRight size={16} className="subtle" />
                    </Link>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </section>
    </main>
  );
}
