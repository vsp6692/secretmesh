// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, ApiError, stepUpURL, type Me, type Organization } from "@/lib/api";
import { useToast } from "@/components/ui";

export interface OrgContext {
  orgId: string;
  /** API path prefix, e.g. /orgs/<id>. */
  base: string;
  /** App path prefix for links. */
  href: string;
  org: Organization;
  me: Me;
  counts: { review: number; overdue: number };
  refreshCounts: () => void;
}

export const OrgCtx = createContext<OrgContext | null>(null);

export function useOrg(): OrgContext {
  const c = useContext(OrgCtx);
  if (!c) throw new Error("useOrg outside AppShell");
  return c;
}

/** Turns an API error into a toast, with re-authentication when needed. */
export function useApiError() {
  const toast = useToast();
  return useCallback(
    (e: unknown) => {
      const here = typeof window === "undefined" ? "/" : window.location.pathname + window.location.search;
      if (e instanceof ApiError && (e.code === "step_up_required" || e.code === "mfa_required" || e.code === "break_glass_denied")) {
        toast({
          tone: "info",
          title: e.code === "step_up_required" ? "Confirm it's you" : "Stronger sign-in needed",
          body: e.code === "step_up_required" ? "This action needs a recent sign-in." : e.message,
          action: (
            <a className="btn sm primary" href={stepUpURL(here)}>
              Sign in again
            </a>
          ),
        });
        return;
      }
      if (e instanceof ApiError && e.status === 403) {
        toast({ tone: "error", title: "Not allowed", body: e.message });
        return;
      }
      toast({ tone: "error", title: "Something went wrong", body: (e as Error).message });
    },
    [toast],
  );
}

/**
 * Loads data for a view and reloads after mutations. `run` shows a success
 * toast or a helpful error.
 */
export function useData<T>(load: () => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const toast = useToast();
  const onError = useApiError();

  useEffect(() => {
    load().then(
      (d) => {
        setData(d);
        setError(null);
      },
      (e: Error) => setError(e),
    );
  }, [load]);

  const reload = useCallback(() => {
    load().then(setData, (e: Error) => setError(e));
  }, [load]);

  const run = useCallback(
    async (action: () => Promise<unknown>, success?: string, body?: string): Promise<boolean> => {
      try {
        await action();
        if (success) toast({ tone: "success", title: success, body });
        reload();
        return true;
      } catch (e) {
        onError(e);
        return false;
      }
    },
    [toast, onError, reload],
  );

  return { data, error, reload, run };
}

/** Fetches /me and the organization; used by the shell. */
export async function loadOrg(orgId: string): Promise<{ me: Me; org: Organization }> {
  const [me, org] = await Promise.all([api<Me>("GET", "/me"), api<Organization>("GET", `/orgs/${encodeURIComponent(orgId)}`)]);
  return { me, org };
}
