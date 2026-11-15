// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import ChangesView from "./changes-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <ChangesView />
    </Suspense>
  );
}
