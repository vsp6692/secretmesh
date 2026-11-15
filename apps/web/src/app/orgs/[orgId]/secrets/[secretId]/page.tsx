import { Suspense } from "react";
import SecretView from "./secret-view";

export default function SecretPage() {
  return (
    <Suspense fallback={null}>
      <SecretView />
    </Suspense>
  );
}
