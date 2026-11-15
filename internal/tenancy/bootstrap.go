package tenancy

import (
	"context"
	"strings"

	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/identity"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

// BootstrapAdminHook grants org_admin in org to the user whose verified email
// equals adminEmail. The tenant scope comes from operator configuration.
func BootstrapAdminHook(s *Store, org Organization, adminEmail string) identity.LoginHook {
	return func(ctx context.Context, u identity.User) error {
		if adminEmail == "" || !u.EmailVerified || !strings.EqualFold(u.Email, adminEmail) {
			return nil
		}
		ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org.ID})
		return s.AddMember(ctx, org.ID, u.ID, auth.RoleOrgAdmin)
	}
}

// AcceptInvitationsHook accepts open invitations for the user's verified email.
func AcceptInvitationsHook(s *Store) identity.LoginHook {
	return func(ctx context.Context, u identity.User) error {
		if !u.EmailVerified {
			return nil
		}
		_, err := s.AcceptInvitations(ctx, u.ID)
		return err
	}
}
