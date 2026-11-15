// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import AuditView from "./audit-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <AuditView />
    </Suspense>
  );
}
