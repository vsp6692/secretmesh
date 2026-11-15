// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package approvals

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Binding is everything an approval authorizes (ADR-0004). Approvers approve
// its hash; the worker recomputes it from stored fields before executing, so
// changing any field (including the staged value, through ValueMAC)
// invalidates the approval. The hash covers a keyed MAC of the value, never
// the value, so it reveals nothing about the secret.
type Binding struct {
	OrganizationID uuid.UUID
	RequestID      uuid.UUID
	Operation      string
	SecretID       uuid.UUID // zero for create
	ConnectionID   uuid.UUID
	EnvironmentID  uuid.UUID
	SecretName     string
	Classification string
	ProviderRef    string
	StagingRef     string
	StagingVersion string
	ValueMAC       []byte
	Nonce          []byte
	ExpiresAt      time.Time
	BreakGlass     bool
}

type canonicalBinding struct {
	V              int    `json:"v"`
	OrganizationID string `json:"organization_id"`
	RequestID      string `json:"request_id"`
	Operation      string `json:"operation"`
	SecretID       string `json:"secret_id"`
	ConnectionID   string `json:"connection_id"`
	EnvironmentID  string `json:"environment_id"`
	SecretName     string `json:"secret_name"`
	Classification string `json:"classification"`
	ProviderRef    string `json:"provider_ref"`
	StagingRef     string `json:"staging_ref"`
	StagingVersion string `json:"staging_version"`
	ValueMAC       string `json:"value_mac"`
	Nonce          string `json:"nonce"`
	ExpiresAt      string `json:"expires_at"`
	BreakGlass     bool   `json:"break_glass"`
}

// Hash returns SHA-256 over the canonical JSON encoding of b.
func (b Binding) Hash() []byte {
	secretID := ""
	if b.SecretID != uuid.Nil {
		secretID = b.SecretID.String()
	}
	enc, _ := json.Marshal(canonicalBinding{
		V:              1,
		OrganizationID: b.OrganizationID.String(),
		RequestID:      b.RequestID.String(),
		Operation:      b.Operation,
		SecretID:       secretID,
		ConnectionID:   b.ConnectionID.String(),
		EnvironmentID:  b.EnvironmentID.String(),
		SecretName:     b.SecretName,
		Classification: b.Classification,
		ProviderRef:    b.ProviderRef,
		StagingRef:     b.StagingRef,
		StagingVersion: b.StagingVersion,
		ValueMAC:       hex.EncodeToString(b.ValueMAC),
		Nonce:          hex.EncodeToString(b.Nonce),
		ExpiresAt:      b.ExpiresAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		BreakGlass:     b.BreakGlass,
	})
	h := sha256.Sum256(enc)
	return h[:]
}
