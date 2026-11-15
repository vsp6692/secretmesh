# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY apps/api apps/api
COPY internal internal
COPY migrations migrations
COPY pkg pkg
COPY policies policies
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/secretmesh-api ./apps/api
# Licence and copyright files of every dependency compiled into the binary.
RUN GOBIN=/tmp/bin go install github.com/google/go-licenses/v2@v2.0.1 \
 && CGO_ENABLED=0 /tmp/bin/go-licenses save ./apps/api --ignore github.com/secretmesh/secretmesh --save_path /out/licenses --force
COPY LICENSE.md /out/licenses/SecretMesh-LICENSE.md
COPY docs/legal/THIRD_PARTY_LICENSES.md /out/licenses/THIRD_PARTY_LICENSES.md

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.licenses="LicenseRef-SecretMesh-SAL-1.0-DRAFT" \
      org.opencontainers.image.source="https://github.com/vsp6692/secretmesh"
COPY --from=build /out/secretmesh-api /secretmesh-api
COPY --from=build /out/licenses /licenses
USER nonroot:nonroot
EXPOSE 8080
ENV SECRETMESH_HTTP_ADDR=:8080
ENTRYPOINT ["/secretmesh-api"]
CMD ["serve"]
