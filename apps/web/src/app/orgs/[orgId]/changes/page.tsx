import { Suspense } from "react";
import ChangesView from "./changes-view";

export default function Page() {
  return (
    <Suspense fallback={null}>
      <ChangesView />
    </Suspense>
  );
}
