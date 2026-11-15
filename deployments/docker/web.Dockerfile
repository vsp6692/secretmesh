# syntax=docker/dockerfile:1
FROM node:25-alpine AS build
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web ./
# Rewrites to the API are resolved at build time.
ARG SECRETMESH_API_URL=http://secretmesh-api:8080
ENV SECRETMESH_API_URL=${SECRETMESH_API_URL} NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:25-alpine
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
