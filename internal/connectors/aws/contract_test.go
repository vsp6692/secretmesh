// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package aws_test

import (
	"testing"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/contract"
)

// The AWS connector passes the same behavioural contract as every other
// provider.
func TestContract(t *testing.T) {
	contract.Run(t, func(t *testing.T) connectors.SecretStore {
		store, _ := env(t)
		return store
	})
}
