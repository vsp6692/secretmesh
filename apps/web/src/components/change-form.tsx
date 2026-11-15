// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

"use client";

import { useState, type FormEvent } from "react";
import { Eye, EyeOff, Siren } from "lucide-react";
import { CLASSIFICATIONS, type Classification, type Connection, type Environment, type Operation } from "@/lib/api";
import { Button, Callout, Field, Segmented } from "@/components/ui";

const MIN_BREAK_GLASS_REASON = 20;

/**
 * Proposes a change. The value lives only in this form's state until it is
 * sent and is cleared afterwards whatever the outcome; it is never stored in
 * the browser.
 */
export function ChangeForm({
  operation,
  secretId,
  environments = [],
  connections = [],
  onSubmit,
  onCancel,
}: {
  operation: Operation;
  secretId?: string;
  environments?: Environment[];
  connections?: Connection[];
  onSubmit: (body: Record<string, unknown>) => Promise<boolean>;
  onCancel?: () => void;
}) {
  const [connection, setConnection] = useState(connections[0]?.id ?? "");
  const [environment, setEnvironment] = useState(environments[0]?.id ?? "");
  const [name, setName] = useState("");
  const [classification, setClassification] = useState<Classification>("confidential");
  const [value, setValue] = useState("");
  const [show, setShow] = useState(false);
  const [reason, setReason] = useState("");
  const [breakGlass, setBreakGlass] = useState(false);
  const [busy, setBusy] = useState(false);

  const env = environments.find((e) => e.id === environment);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const body: Record<string, unknown> = { operation, reason };
    if (operation === "create") {
      Object.assign(body, { connection_id: connection, environment_id: environment, name: name.trim(), classification });
    } else {
      body.secret_id = secretId;
    }
    if (operation !== "delete") body.value = value;
    if (breakGlass) body.break_glass = true;
    setBusy(true);
    let ok = false;
    try {
      ok = await onSubmit(body);
    } finally {
      setValue("");
      setShow(false);
      setBusy(false);
    }
    if (ok) {
      setName("");
      setReason("");
      setBreakGlass(false);
    }
  }

  const reasonTooShort = breakGlass && reason.trim().length < MIN_BREAK_GLASS_REASON;

  return (
    <form className="form" onSubmit={submit} autoComplete="off">
      {operation === "create" && (
        <>
          <Field label="Name" hint="Letters, digits and / _ + = . @ -, e.g. payments/db-password" htmlFor="cf-name">
            <input id="cf-name" className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="app/db-password" />
          </Field>
          <div className="form-row">
            <Field label="Cloud connection" htmlFor="cf-conn">
              <select id="cf-conn" className="select" required value={connection} onChange={(e) => setConnection(e.target.value)}>
                {connections.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.provider})
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Environment" htmlFor="cf-env">
              <select id="cf-env" className="select" required value={environment} onChange={(e) => setEnvironment(e.target.value)}>
                {environments.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.name} ({e.kind})
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="field">
            <span className="label">Classification</span>
            <Segmented
              options={CLASSIFICATIONS.map((c) => ({ id: c, label: c[0].toUpperCase() + c.slice(1) }))}
              value={classification}
              onChange={setClassification}
            />
          </div>
        </>
      )}

      {operation !== "delete" && (
        <Field
          label={operation === "create" ? "Value" : "New value"}
          hint="Staged in your cloud vault, never stored by SecretMesh. It goes live only after the required approvals."
          htmlFor="cf-value"
        >
          <div className="input-icon" style={{ position: "relative" }}>
            <input
              id="cf-value"
              className="input mono"
              style={{ width: "100%", paddingRight: 40 }}
              required
              type={show ? "text" : "password"}
              autoComplete="new-password"
              spellCheck={false}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
            <button type="button" className="icon-btn" style={{ position: "absolute", right: 2 }} onClick={() => setShow(!show)} aria-label={show ? "Hide value" : "Show value"}>
              {show ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
        </Field>
      )}

      {operation === "delete" && (
        <Callout tone="warning" title="The secret will be scheduled for deletion in the provider">
          AWS keeps it recoverable for 7 days. Applications reading it will start failing.
        </Callout>
      )}

      <Field label={breakGlass ? "Incident and justification" : "Reason"} hint={breakGlass ? `At least ${MIN_BREAK_GLASS_REASON} characters. Shown to reviewers and auditors.` : "Helps approvers decide quickly."} htmlFor="cf-reason">
        <textarea
          id="cf-reason"
          className="textarea"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required={breakGlass}
          maxLength={1000}
          placeholder={breakGlass ? "INC-1234: database credential leaked in CI logs" : "Why is this change needed?"}
        />
      </Field>

      <label className="check">
        <input type="checkbox" checked={breakGlass} onChange={(e) => setBreakGlass(e.target.checked)} />
        <span>
          <strong style={{ fontWeight: 550 }}>
            <Siren size={14} style={{ verticalAlign: -2, marginRight: 4 }} />
            Break-glass
          </strong>
          <span className="muted" style={{ display: "block", fontSize: 13 }}>
            Apply without prior approval. Emergencies only.
          </span>
        </span>
      </label>
      {breakGlass && (
        <Callout tone="danger" title="Emergency change">
          Needs the break_glass role and an MFA sign-in within the last 5 minutes. The security team and admins are alerted
          and it is flagged for review.
        </Callout>
      )}
      {!breakGlass && env?.kind === "production" && (
        <Callout tone="info" title="Production change">
          Needs approval from someone else, made with MFA.
        </Callout>
      )}

      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
        <Button type="submit" variant={operation === "delete" || breakGlass ? "danger" : "primary"} loading={busy} disabled={reasonTooShort}>
          {breakGlass ? "Apply now (break-glass)" : operation === "delete" ? "Request deletion" : operation === "update" ? "Request change" : "Request secret"}
        </Button>
      </div>
    </form>
  );
}
