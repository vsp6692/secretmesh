// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import SecretsView from "./secrets-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <SecretsView />
    </Suspense>
  );
}
