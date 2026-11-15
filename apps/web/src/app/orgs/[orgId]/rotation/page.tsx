// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import RotationView from "./rotation-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <RotationView />
    </Suspense>
  );
}
