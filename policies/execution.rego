# Execution policy (gate 4, ADR-0006). The worker evaluates it immediately
# before every provider call, with input built from the database, never from
# the job payload. Any deny reason blocks execution.
package secretmesh.execution

default allow := false

allow if count(deny_reasons) == 0

deny_reasons contains "not_authenticated" if not input.identity.authenticated

deny_reasons contains "not_authorized" if not input.authorization.allowed

deny_reasons contains "not_approved" if input.approval.status != "approved"

deny_reasons contains "expired" if input.request.expired

deny_reasons contains "payload_changed" if not input.request.binding_valid

deny_reasons contains "insufficient_approvals" if input.approval.count < input.approval.required

# Break-glass: an emergency change without prior approval, by a person
# holding the break_glass role whose session used MFA. It is flagged and
# audited for after-the-fact review.
break_glass if {
	input.request.break_glass
	input.identity.kind == "user"
	input.identity.mfa_verified
}

deny_reasons contains "break_glass_requires_mfa" if {
	input.request.break_glass
	not break_glass
}

deny_reasons contains "production_requires_approval" if {
	input.resource.environment == "production"
	input.approval.count < 1
	not break_glass
}

deny_reasons contains "production_requires_mfa" if {
	input.resource.environment == "production"
	not input.approval.approvers_mfa_verified
	not break_glass
}

# Approvers already needed MFA to reach the organization; this covers the
# requester's session. API tokens are created from MFA sessions in such
# organizations.
deny_reasons contains "organization_requires_mfa" if {
	input.organization.require_mfa
	input.identity.kind == "user"
	not input.identity.mfa_verified
}
