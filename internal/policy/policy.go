// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package policy evaluates the execution policy (gate 4) with embedded OPA.
package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Input is the execution policy input. Every field is derived from database
// state at execution time.
type Input struct {
	Identity struct {
		Authenticated bool   `json:"authenticated"`
		Kind          string `json:"kind"`
		MFAVerified   bool   `json:"mfa_verified"`
	} `json:"identity"`
	Authorization struct {
		Allowed bool `json:"allowed"`
	} `json:"authorization"`
	Resource struct {
		Environment    string `json:"environment"`
		Classification string `json:"classification"`
		Provider       string `json:"provider"`
	} `json:"resource"`
	Request struct {
		Operation    string `json:"operation"`
		Expired      bool   `json:"expired"`
		BindingValid bool   `json:"binding_valid"`
		// BreakGlass is true only if the request is flagged and the requester
		// still holds the break_glass role.
		BreakGlass bool `json:"break_glass"`
	} `json:"request"`
	Approval struct {
		Status               string `json:"status"`
		Required             int    `json:"required"`
		Count                int    `json:"count"`
		ApproversMFAVerified bool   `json:"approvers_mfa_verified"`
	} `json:"approval"`
	Organization struct {
		RequireMFA bool `json:"require_mfa"`
	} `json:"organization"`
}

// Decision is the policy result. Reasons are sorted.
type Decision struct {
	Allow   bool
	Reasons []string
}

type Engine struct {
	query rego.PreparedEvalQuery
}

// RotationInput is the rotation policy input (package secretmesh.rotation),
// also derived from database state immediately before the provider call.
type RotationInput struct {
	// Trigger is "schedule" (the rotation policy) or "manual" (a person).
	Trigger  string `json:"trigger"`
	Identity struct {
		Authenticated bool   `json:"authenticated"`
		Kind          string `json:"kind"` // system or user
		MFAVerified   bool   `json:"mfa_verified"`
	} `json:"identity"`
	Authorization struct {
		Allowed bool `json:"allowed"`
	} `json:"authorization"`
	Resource struct {
		Environment    string `json:"environment"`
		Classification string `json:"classification"`
		Provider       string `json:"provider"`
	} `json:"resource"`
	Policy struct {
		Exists   bool   `json:"exists"`
		Enabled  bool   `json:"enabled"`
		Strategy string `json:"strategy"`
	} `json:"policy"`
	Secret struct {
		Active bool `json:"active"`
		// ChangeInProgress: an open change request targets the secret.
		ChangeInProgress bool `json:"change_in_progress"`
	} `json:"secret"`
	Organization struct {
		RequireMFA bool `json:"require_mfa"`
	} `json:"organization"`
}

// New compiles module, which must define package secretmesh.execution with
// boolean "allow" and set "deny_reasons".
func New(ctx context.Context, module []byte) (*Engine, error) {
	return compile(ctx, "execution", module)
}

// NewRotation compiles a rotation policy (package secretmesh.rotation).
func NewRotation(ctx context.Context, module []byte) (*Engine, error) {
	return compile(ctx, "rotation", module)
}

func compile(ctx context.Context, pkg string, module []byte) (*Engine, error) {
	q, err := rego.New(
		rego.Query("data.secretmesh."+pkg),
		rego.Module(pkg+".rego", string(module)),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile %s policy: %w", pkg, err)
	}
	return &Engine{query: q}, nil
}

// Evaluate fails closed: errors and malformed results deny. in is an Input
// or RotationInput.
func (e *Engine) Evaluate(ctx context.Context, in any) (Decision, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{Reasons: []string{"policy_error"}}, fmt.Errorf("evaluate execution policy: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{Reasons: []string{"policy_undefined"}}, nil
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{Reasons: []string{"policy_undefined"}}, nil
	}
	var d Decision
	if reasons, ok := doc["deny_reasons"].([]any); ok {
		for _, r := range reasons {
			if s, ok := r.(string); ok {
				d.Reasons = append(d.Reasons, s)
			}
		}
	}
	slices.Sort(d.Reasons)
	allow, _ := doc["allow"].(bool)
	d.Allow = allow && len(d.Reasons) == 0
	if !d.Allow && len(d.Reasons) == 0 {
		d.Reasons = []string{"policy_denied"}
	}
	return d, nil
}
