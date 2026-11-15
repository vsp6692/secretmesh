// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import { Suspense } from "react";
import SettingsView from "./settings-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <SettingsView />
    </Suspense>
  );
}
