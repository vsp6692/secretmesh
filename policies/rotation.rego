# SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

# Rotation policy (ADR-0011). The rotation worker evaluates it immediately
# before asking the provider to rotate, with input built from the database.
# A rotation policy is the standing authorization for scheduled rotations;
# rotate-now requests are additionally bound to the person asking.
package secretmesh.rotation

default allow := false

allow if count(deny_reasons) == 0

deny_reasons contains "no_rotation_policy" if not input.policy.exists

deny_reasons contains "unsupported_strategy" if input.policy.strategy != "native"

deny_reasons contains "secret_inactive" if not input.secret.active

# Rotating while a change request is open could overwrite the reviewed value,
# or be overwritten by it.
deny_reasons contains "change_in_progress" if input.secret.change_in_progress

deny_reasons contains "policy_disabled" if {
	input.trigger == "schedule"
	not input.policy.enabled
}

deny_reasons contains "not_authenticated" if {
	input.trigger == "manual"
	not input.identity.authenticated
}

deny_reasons contains "not_authorized" if {
	input.trigger == "manual"
	not input.authorization.allowed
}

deny_reasons contains "production_requires_mfa" if {
	input.trigger == "manual"
	input.resource.environment == "production"
	not input.identity.mfa_verified
}

deny_reasons contains "organization_requires_mfa" if {
	input.trigger == "manual"
	input.organization.require_mfa
	not input.identity.mfa_verified
}
