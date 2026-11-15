// Package keys provides the cryptographic keys SecretMesh uses for approval
// binding (per-tenant HMAC, ADR-0004) and audit checkpoint signatures.
//
// Keys never leave this package. LocalKeyring derives them from a master key
// held in process memory; a KMS-backed keyring replaces it in production
// deployments (ADR-0009).
package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// Purposes separate MAC keys used for different things.
const (
	PurposeValueMAC = "approval-value-mac"
)

// Keyring computes tenant MACs and signs audit checkpoints.
type Keyring interface {
	// TenantMAC returns HMAC-SHA256(k, data) with a key unique to org and purpose.
	TenantMAC(ctx context.Context, org uuid.UUID, purpose string, data []byte) ([]byte, error)
	// Sign signs msg with the current audit signing key.
	Sign(ctx context.Context, msg []byte) (keyID string, sig []byte, err error)
	// Verify checks a signature made by Sign.
	Verify(ctx context.Context, keyID string, msg, sig []byte) error
}

// ErrBadSignature is returned by Verify.
var ErrBadSignature = errors.New("invalid signature")

// LocalKeyring derives all keys from a 32-byte master key with HKDF-SHA256.
type LocalKeyring struct {
	master  []byte
	signing ed25519.PrivateKey
	keyID   string
}

// NewLocalKeyring requires a master key of exactly 32 bytes.
func NewLocalKeyring(master sensitive.Value) (*LocalKeyring, error) {
	if len(master.Reveal()) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(master.Reveal()))
	}
	k := &LocalKeyring{master: append([]byte(nil), master.Reveal()...)}
	seed, err := k.derive("secretmesh/v1/audit-signing", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	k.signing = ed25519.NewKeyFromSeed(seed)
	pub := sha256.Sum256(k.signing.Public().(ed25519.PublicKey))
	k.keyID = "local-ed25519:" + hex.EncodeToString(pub[:8])
	return k, nil
}

func (k *LocalKeyring) derive(info string, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, k.master, nil, info, n)
}

func (k *LocalKeyring) TenantMAC(_ context.Context, org uuid.UUID, purpose string, data []byte) ([]byte, error) {
	if org == uuid.Nil || purpose == "" {
		return nil, errors.New("tenant MAC requires an organization and purpose")
	}
	key, err := k.derive("secretmesh/v1/tenant-mac/"+purpose+"/"+org.String(), 32)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil), nil
}

func (k *LocalKeyring) Sign(_ context.Context, msg []byte) (string, []byte, error) {
	return k.keyID, ed25519.Sign(k.signing, msg), nil
}

func (k *LocalKeyring) Verify(_ context.Context, keyID string, msg, sig []byte) error {
	if keyID != k.keyID || !ed25519.Verify(k.signing.Public().(ed25519.PublicKey), msg, sig) {
		return ErrBadSignature
	}
	return nil
}
