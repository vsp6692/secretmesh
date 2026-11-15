// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package httpapi wires the HTTP router: auth endpoints, health checks and the
// /api/v1 handlers generated from contracts/openapi/secretmesh.yaml.
package httpapi

//go:generate go tool oapi-codegen -config oapi-codegen.yaml ../../contracts/openapi/secretmesh.yaml
