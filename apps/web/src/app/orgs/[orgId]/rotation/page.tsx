import { Suspense } from "react";
import RotationView from "./rotation-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <RotationView />
    </Suspense>
  );
}
