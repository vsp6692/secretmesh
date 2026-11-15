// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

import type { NextConfig } from "next";

// The browser only talks to this origin; /api and /auth are proxied to the Go
// API so session cookies stay first-party and no CORS is needed.
// Rewrites are resolved at build time: set SECRETMESH_API_URL before `next build`.
const apiURL = process.env.SECRETMESH_API_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  output: "standalone",
  poweredByHeader: false,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiURL}/api/:path*` },
      { source: "/auth/:path*", destination: `${apiURL}/auth/:path*` },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
