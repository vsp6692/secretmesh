// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import SecretView from "./secret-view";

export default function SecretPage() {
  return (
    <Suspense fallback={null}>
      <SecretView />
    </Suspense>
  );
}
