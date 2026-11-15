package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"
)

// KMSKeyring keeps key material in AWS KMS (ADR-0010):
//
//   - Approval MACs use an HMAC_256 key via GenerateMac. The message is
//     domain-separated by purpose and organization and carries SHA-256 of the
//     data, since KMS accepts at most 4 KiB.
//   - Checkpoints are signed with an ECC_NIST_P256 key; verification uses the
//     cached public key, so it needs no KMS call.
type KMSKeyring struct {
	client   *kms.Client
	macKeyID string
	signARN  string
	pub      *ecdsa.PublicKey
	// fallback verifies checkpoints signed before switching keyrings.
	fallback Keyring
}

// NewKMSKeyring checks both keys and loads the signing public key.
func NewKMSKeyring(ctx context.Context, client *kms.Client, macKeyID, signKeyID string, fallback Keyring) (*KMSKeyring, error) {
	mac, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(macKeyID)})
	if err != nil {
		return nil, fmt.Errorf("describe MAC key: %w", err)
	}
	if mac.KeyMetadata.KeyUsage != kmstypes.KeyUsageTypeGenerateVerifyMac {
		return nil, errors.New("MAC key must have key usage GENERATE_VERIFY_MAC")
	}
	sign, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(signKeyID)})
	if err != nil {
		return nil, fmt.Errorf("describe signing key: %w", err)
	}
	if sign.KeyMetadata.KeyUsage != kmstypes.KeyUsageTypeSignVerify || sign.KeyMetadata.KeySpec != kmstypes.KeySpecEccNistP256 {
		return nil, errors.New("signing key must be an ECC_NIST_P256 SIGN_VERIFY key")
	}
	pubOut, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(signKeyID)})
	if err != nil {
		return nil, fmt.Errorf("get signing public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(pubOut.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse signing public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("signing key is not ECDSA")
	}
	return &KMSKeyring{client: client, macKeyID: aws.ToString(mac.KeyMetadata.Arn),
		signARN: aws.ToString(sign.KeyMetadata.Arn), pub: pub, fallback: fallback}, nil
}

func (k *KMSKeyring) TenantMAC(ctx context.Context, org uuid.UUID, purpose string, data []byte) ([]byte, error) {
	if org == uuid.Nil || purpose == "" {
		return nil, errors.New("tenant MAC requires an organization and purpose")
	}
	sum := sha256.Sum256(data)
	msg := []byte("secretmesh/v1/" + purpose + "/" + org.String() + "\n" + hex.EncodeToString(sum[:]))
	out, err := k.client.GenerateMac(ctx, &kms.GenerateMacInput{
		KeyId: aws.String(k.macKeyID), Message: msg, MacAlgorithm: kmstypes.MacAlgorithmSpecHmacSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("kms generate mac: %w", err)
	}
	return out.Mac, nil
}

func (k *KMSKeyring) Sign(ctx context.Context, msg []byte) (string, []byte, error) {
	out, err := k.client.Sign(ctx, &kms.SignInput{
		KeyId: aws.String(k.signARN), Message: msg, MessageType: kmstypes.MessageTypeRaw,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return "", nil, fmt.Errorf("kms sign: %w", err)
	}
	return k.signARN, out.Signature, nil
}

func (k *KMSKeyring) Verify(ctx context.Context, keyID string, msg, sig []byte) error {
	if keyID != k.signARN {
		if k.fallback != nil {
			return k.fallback.Verify(ctx, keyID, msg, sig)
		}
		return ErrBadSignature
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(k.pub, digest[:], sig) {
		return ErrBadSignature
	}
	return nil
}
