import { Suspense } from "react";
import AuditView from "./audit-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <AuditView />
    </Suspense>
  );
}
