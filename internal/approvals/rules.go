// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package approvals

import (
	"errors"
	"fmt"
)

// Rule requires a number of approvals for matching changes. "*" matches any
// value.
type Rule struct {
	Environment       string `json:"environment"`
	Operation         string `json:"operation"`
	Classification    string `json:"classification"`
	RequiredApprovals int    `json:"required_approvals"`
}

// Policy is an organization's approval policy. The requirement for a change
// is the maximum over all matching rules, so adding a rule can only make
// approval stricter.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// DefaultPolicy follows the blueprint: production changes need one approver,
// production deletes two, and restricted secrets one everywhere.
var DefaultPolicy = Policy{Rules: []Rule{
	{Environment: "production", Operation: "*", Classification: "*", RequiredApprovals: 1},
	{Environment: "production", Operation: "delete", Classification: "*", RequiredApprovals: 2},
	{Environment: "*", Operation: "*", Classification: "restricted", RequiredApprovals: 1},
}}

const MaxApprovals = 5

func (p Policy) Required(environment, operation, classification string) int {
	n := 0
	for _, r := range p.Rules {
		if match(r.Environment, environment) && match(r.Operation, operation) && match(r.Classification, classification) {
			n = max(n, r.RequiredApprovals)
		}
	}
	return n
}

func match(pattern, v string) bool { return pattern == "*" || pattern == v }

var (
	validEnvironments    = []string{"*", "development", "staging", "production"}
	validOperations      = []string{"*", "create", "update", "delete"}
	validClassifications = []string{"*", "internal", "confidential", "restricted"}
)

// ErrInvalidPolicy is returned by Validate.
var ErrInvalidPolicy = errors.New("invalid approval policy")

func (p Policy) Validate() error {
	if len(p.Rules) > 50 {
		return fmt.Errorf("%w: at most 50 rules", ErrInvalidPolicy)
	}
	for i, r := range p.Rules {
		switch {
		case !contains(validEnvironments, r.Environment):
			return fmt.Errorf("%w: rule %d: unknown environment %q", ErrInvalidPolicy, i, r.Environment)
		case !contains(validOperations, r.Operation):
			return fmt.Errorf("%w: rule %d: unknown operation %q", ErrInvalidPolicy, i, r.Operation)
		case !contains(validClassifications, r.Classification):
			return fmt.Errorf("%w: rule %d: unknown classification %q", ErrInvalidPolicy, i, r.Classification)
		case r.RequiredApprovals < 0 || r.RequiredApprovals > MaxApprovals:
			return fmt.Errorf("%w: rule %d: required_approvals must be 0-%d", ErrInvalidPolicy, i, MaxApprovals)
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
