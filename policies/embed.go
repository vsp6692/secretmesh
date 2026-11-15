// Package policies embeds the built-in OPA policies.
package policies

import _ "embed"

// Execution is the default execution policy (package secretmesh.execution).
//
//go:embed execution.rego
var Execution []byte

// Rotation is the default rotation policy (package secretmesh.rotation).
//
//go:embed rotation.rego
var Rotation []byte
