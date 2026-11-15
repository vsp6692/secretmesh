// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecretMesh",
  description: "Multi-cloud secrets governance",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
