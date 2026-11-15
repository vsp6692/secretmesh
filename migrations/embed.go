// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package migrations embeds the PostgreSQL schema migrations.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
