// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package fake_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/connectors/contract"
	"github.com/secretmesh/secretmesh/internal/connectors/fake"
)

func TestContract(t *testing.T) {
	contract.Run(t, func(t *testing.T) connectors.SecretStore {
		s, err := fake.New().Factory(connectors.Connection{ID: uuid.New(), Provider: fake.Provider})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
