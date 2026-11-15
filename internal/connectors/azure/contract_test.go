// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package azure_test

import (
	"testing"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/contract"
)

// The Azure connector passes the same behavioural contract as every other
// provider, against a fresh in-memory vault per test.
func TestContract(t *testing.T) {
	contract.Run(t, func(t *testing.T) connectors.SecretStore {
		return newFixture(t).store
	})
}
