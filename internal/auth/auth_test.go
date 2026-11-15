// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAccessCan(t *testing.T) {
	user := Principal{Kind: KindUser, UserID: uuid.New()}
	token := func(scopes ...Permission) Principal {
		return Principal{Kind: KindAPIToken, UserID: uuid.New(), TokenID: uuid.New(), TokenScopes: scopes}
	}

	tests := []struct {
		name string
		a    Access
		perm Permission
		want bool
	}{
		{"admin manages members", Access{Principal: user, Role: RoleOrgAdmin}, MembersWrite, true},
		{"member reads members", Access{Principal: user, Role: RoleMember}, MembersRead, true},
		{"member cannot manage members", Access{Principal: user, Role: RoleMember}, MembersWrite, false},
		{"member cannot manage tokens", Access{Principal: user, Role: RoleMember}, TokensManage, false},
		{"unknown role has nothing", Access{Principal: user, Role: "owner"}, OrgRead, false},
		{"zero principal has nothing", Access{Role: RoleOrgAdmin}, OrgRead, false},
		{"token within scope", Access{Principal: token(MembersWrite), Role: RoleOrgAdmin}, MembersWrite, true},
		{"token outside scope", Access{Principal: token(OrgRead), Role: RoleOrgAdmin}, MembersWrite, false},
		{"token scope beyond creator role", Access{Principal: token(MembersWrite), Role: RoleMember}, MembersWrite, false},
		{"token cannot manage tokens even if scoped", Access{Principal: token(TokensManage), Role: RoleOrgAdmin}, TokensManage, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Can(tt.perm); got != tt.want {
				t.Fatalf("Can(%s) = %v, want %v", tt.perm, got, tt.want)
			}
		})
	}
}

func TestAuthenticatedWithin(t *testing.T) {
	now := time.Now()
	recent := Principal{Kind: KindUser, AuthTime: now.Add(-time.Minute)}
	if !recent.AuthenticatedWithin(5*time.Minute, now) {
		t.Error("recent login must qualify")
	}
	if recent.AuthenticatedWithin(30*time.Second, now) {
		t.Error("old login must not qualify")
	}
	if (Principal{Kind: KindUser}).AuthenticatedWithin(time.Hour, now) {
		t.Error("unknown auth time must not qualify")
	}
	if (Principal{Kind: KindAPIToken, AuthTime: now}).AuthenticatedWithin(time.Hour, now) {
		t.Error("API tokens can never satisfy step-up")
	}
	if ValidTokenScope(TokensManage) {
		t.Error("tokens:manage must not be grantable to tokens")
	}
}

func TestAccessCanOn(t *testing.T) {
	staging, prod := uuid.New(), uuid.New()
	user := Principal{Kind: KindUser, UserID: uuid.New()}
	dev := Access{Principal: user, Role: RoleMember, Bindings: []Binding{{Role: RoleDeveloper, EnvironmentID: staging}}}
	admin := Access{Principal: user, Role: RoleOrgAdmin}
	auditor := Access{Principal: user, Role: RoleMember, Bindings: []Binding{{Role: RoleAuditor}}}
	envAuditor := Access{Principal: user, Role: RoleMember, Bindings: []Binding{{Role: RoleAuditor, EnvironmentID: staging}}}
	token := func(b []Binding, scopes ...Permission) Access {
		return Access{Principal: Principal{Kind: KindAPIToken, TokenScopes: scopes}, Role: RoleMember, Bindings: b}
	}
	approverToken := token([]Binding{{Role: RoleApprover}}, ScopeSecretsRead, ScopeSecretsWrite)

	tests := []struct {
		name string
		a    Access
		perm Permission
		env  uuid.UUID
		want bool
	}{
		{"developer updates in bound environment", dev, SecretUpdate, staging, true},
		{"developer cannot touch production", dev, SecretUpdate, prod, false},
		{"developer cannot delete", dev, SecretDelete, staging, false},
		{"developer cannot approve", dev, ApprovalDecide, staging, false},
		{"org admin has no implicit resource permissions", admin, SecretRead, staging, false},
		{"org-wide auditor reads audit", auditor, AuditRead, uuid.Nil, true},
		{"environment auditor cannot read org-wide audit", envAuditor, AuditRead, uuid.Nil, false},
		{"token within scope and binding", token(dev.Bindings, ScopeSecretsWrite), SecretUpdate, staging, true},
		{"token without scope", token(dev.Bindings, ScopeSecretsRead), SecretUpdate, staging, false},
		{"token scope beyond binding", token(dev.Bindings, ScopeSecretsWrite), SecretDelete, staging, false},
		{"tokens never approve", approverToken, ApprovalDecide, staging, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.CanOn(tt.perm, tt.env); got != tt.want {
				t.Fatalf("CanOn(%s) = %v, want %v", tt.perm, got, tt.want)
			}
		})
	}
}
