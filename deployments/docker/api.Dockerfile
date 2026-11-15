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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secretmesh-api /secretmesh-api
USER nonroot:nonroot
EXPOSE 8080
ENV SECRETMESH_HTTP_ADDR=:8080
ENTRYPOINT ["/secretmesh-api"]
CMD ["serve"]
