package policy

import (
	"context"
	"slices"
	"testing"

	"github.com/secretmesh/secretmesh/policies"
)

func approved(env string) Input {
	var in Input
	in.Identity.Authenticated = true
	in.Authorization.Allowed = true
	in.Resource.Environment = env
	in.Request.BindingValid = true
	in.Approval.Status = "approved"
	return in
}

func TestExecutionPolicy(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx, policies.Execution)
	if err != nil {
		t.Fatal(err)
	}

	prod := approved("production")
	prod.Approval.Required, prod.Approval.Count, prod.Approval.ApproversMFAVerified = 1, 1, true

	tests := []struct {
		name   string
		mutate func(*Input)
		base   Input
		reason string // "" means allow
	}{
		{"staging without approval", nil, approved("staging"), ""},
		{"approved production", nil, prod, ""},
		{"unauthenticated", func(i *Input) { i.Identity.Authenticated = false }, prod, "not_authenticated"},
		{"unauthorized", func(i *Input) { i.Authorization.Allowed = false }, prod, "not_authorized"},
		{"pending", func(i *Input) { i.Approval.Status = "pending" }, prod, "not_approved"},
		{"expired", func(i *Input) { i.Request.Expired = true }, prod, "expired"},
		{"payload changed", func(i *Input) { i.Request.BindingValid = false }, prod, "payload_changed"},
		{"too few approvals", func(i *Input) { i.Approval.Required = 2 }, prod, "insufficient_approvals"},
		{"production without approval", func(i *Input) { i.Approval.Count, i.Approval.Required = 0, 0 }, prod, "production_requires_approval"},
		{"production without MFA", func(i *Input) { i.Approval.ApproversMFAVerified = false }, prod, "production_requires_mfa"},
		{"organization requires MFA", func(i *Input) { i.Organization.RequireMFA, i.Identity.Kind = true, "user" }, approved("staging"), "organization_requires_mfa"},
		{"break-glass production change", func(i *Input) {
			i.Approval.Count, i.Approval.Required, i.Approval.ApproversMFAVerified = 0, 0, false
			i.Request.BreakGlass, i.Identity.Kind, i.Identity.MFAVerified = true, "user", true
		}, prod, ""},
		{"break-glass without MFA", func(i *Input) {
			i.Approval.Count, i.Approval.Required = 0, 0
			i.Request.BreakGlass, i.Identity.Kind = true, "user"
		}, prod, "break_glass_requires_mfa"},
		{"break-glass by token", func(i *Input) {
			i.Approval.Count, i.Approval.Required = 0, 0
			i.Request.BreakGlass, i.Identity.Kind, i.Identity.MFAVerified = true, "api_token", true
		}, prod, "production_requires_approval"},
		{"organization MFA satisfied", func(i *Input) {
			i.Organization.RequireMFA, i.Identity.Kind, i.Identity.MFAVerified = true, "user", true
		}, approved("staging"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.base
			if tt.mutate != nil {
				tt.mutate(&in)
			}
			d, err := e.Evaluate(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			if tt.reason == "" {
				if !d.Allow {
					t.Fatalf("denied: %v", d.Reasons)
				}
				return
			}
			if d.Allow || !slices.Contains(d.Reasons, tt.reason) {
				t.Fatalf("want deny %q, got allow=%v reasons=%v", tt.reason, d.Allow, d.Reasons)
			}
		})
	}
}

func TestPolicyFailsClosed(t *testing.T) {
	ctx := context.Background()
	e, err := New(ctx, []byte("package secretmesh.execution\n\nallow := true\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A policy that allows without defining deny_reasons still allows; one that
	// leaves allow undefined denies.
	if d, _ := e.Evaluate(ctx, Input{}); !d.Allow {
		t.Fatal("explicit allow ignored")
	}
	e, _ = New(ctx, []byte("package secretmesh.execution\n\nother := 1\n"))
	if d, _ := e.Evaluate(ctx, Input{}); d.Allow {
		t.Fatal("undefined allow must deny")
	}
	if _, err := New(ctx, []byte("package secretmesh.execution\nallow if {")); err == nil {
		t.Fatal("invalid policy compiled")
	}
}

func TestRotationPolicy(t *testing.T) {
	ctx := context.Background()
	e, err := NewRotation(ctx, policies.Rotation)
	if err != nil {
		t.Fatal(err)
	}
	var sched RotationInput
	sched.Trigger = "schedule"
	sched.Identity.Kind, sched.Identity.Authenticated = "system", true
	sched.Resource.Environment = "production"
	sched.Policy.Exists, sched.Policy.Enabled, sched.Policy.Strategy = true, true, "native"
	sched.Secret.Active = true
	manual := sched
	manual.Trigger = "manual"
	manual.Identity.Kind, manual.Identity.MFAVerified = "user", true
	manual.Authorization.Allowed = true

	tests := []struct {
		name   string
		base   RotationInput
		mutate func(*RotationInput)
		reason string
	}{
		{"scheduled", sched, nil, ""},
		{"rotate now", manual, nil, ""},
		{"rotate now while disabled", manual, func(i *RotationInput) { i.Policy.Enabled = false }, ""},
		{"no policy", sched, func(i *RotationInput) { i.Policy.Exists = false }, "no_rotation_policy"},
		{"manual strategy", sched, func(i *RotationInput) { i.Policy.Strategy = "manual" }, "unsupported_strategy"},
		{"disabled", sched, func(i *RotationInput) { i.Policy.Enabled = false }, "policy_disabled"},
		{"deleted secret", sched, func(i *RotationInput) { i.Secret.Active = false }, "secret_inactive"},
		{"open change", sched, func(i *RotationInput) { i.Secret.ChangeInProgress = true }, "change_in_progress"},
		{"lost access", manual, func(i *RotationInput) { i.Authorization.Allowed = false }, "not_authorized"},
		{"left organization", manual, func(i *RotationInput) { i.Identity.Authenticated = false }, "not_authenticated"},
		{"production without MFA", manual, func(i *RotationInput) { i.Identity.MFAVerified = false }, "production_requires_mfa"},
		{"organization requires MFA", manual, func(i *RotationInput) {
			i.Resource.Environment, i.Identity.MFAVerified, i.Organization.RequireMFA = "staging", false, true
		}, "organization_requires_mfa"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.base
			if tt.mutate != nil {
				tt.mutate(&in)
			}
			d, err := e.Evaluate(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			if tt.reason == "" && !d.Allow {
				t.Fatalf("denied: %v", d.Reasons)
			}
			if tt.reason != "" && (d.Allow || !slices.Contains(d.Reasons, tt.reason)) {
				t.Fatalf("want %s, got allow=%v %v", tt.reason, d.Allow, d.Reasons)
			}
		})
	}
	// A module for the wrong package leaves the query undefined: deny.
	if wrong, err := NewRotation(ctx, policies.Execution); err == nil {
		if d, _ := wrong.Evaluate(ctx, sched); d.Allow {
			t.Fatal("execution policy allowed a rotation")
		}
	}
}
