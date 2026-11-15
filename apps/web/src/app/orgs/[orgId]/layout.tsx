// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import { AppShell } from "@/components/shell";

// The organization ID is only known at request time, so it is read inside a
// Suspense boundary (required with cacheComponents).
export default function OrgLayout({ children, params }: LayoutProps<"/orgs/[orgId]">) {
  return (
    <Suspense fallback={null}>
      {params.then(({ orgId }) => (
        <AppShell orgId={orgId}>{children}</AppShell>
      ))}
    </Suspense>
  );
}
