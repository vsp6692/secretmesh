# syntax=docker/dockerfile:1
FROM node:24-alpine AS build
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web ./
# Licence and copyright files of every production dependency.
RUN npx --yes license-checker-rseidelsohn@4.4.2 --production --excludePrivatePackages --files /out/licenses/npm > /dev/null
COPY LICENSE.md /out/licenses/SecretMesh-LICENSE.md
COPY docs/legal/THIRD_PARTY_LICENSES.md /out/licenses/THIRD_PARTY_LICENSES.md
# Rewrites to the API are resolved at build time.
ARG SECRETMESH_API_URL=http://secretmesh-api:8080
ENV SECRETMESH_API_URL=${SECRETMESH_API_URL} NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
LABEL org.opencontainers.image.licenses="LicenseRef-SecretMesh-SAL-1.0-DRAFT" \
      org.opencontainers.image.source="https://github.com/vsp6692/secretmesh"
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public
COPY --from=build /out/licenses /licenses
USER node
EXPOSE 3000
CMD ["node", "server.js"]
