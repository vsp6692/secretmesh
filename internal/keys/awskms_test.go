// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package keys_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func TestKMSKeyring(t *testing.T) {
	endpoint := os.Getenv("SECRETMESH_TEST_AWS_ENDPOINT")
	if endpoint == "" {
		t.Skip("SECRETMESH_TEST_AWS_ENDPOINT not set")
	}
	ctx := context.Background()
	client := kms.New(kms.Options{Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")})
	macKey, err := client.CreateKey(ctx, &kms.CreateKeyInput{KeyUsage: kmstypes.KeyUsageTypeGenerateVerifyMac, KeySpec: kmstypes.KeySpecHmac256})
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := client.CreateKey(ctx, &kms.CreateKeyInput{KeyUsage: kmstypes.KeyUsageTypeSignVerify, KeySpec: kmstypes.KeySpecEccNistP256})
	if err != nil {
		t.Fatal(err)
	}
	local, _ := keys.NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{9}, 32)))

	if _, err := keys.NewKMSKeyring(ctx, client, aws.ToString(signKey.KeyMetadata.KeyId), aws.ToString(signKey.KeyMetadata.KeyId), nil); err == nil {
		t.Fatal("signing key accepted as MAC key")
	}
	k, err := keys.NewKMSKeyring(ctx, client, aws.ToString(macKey.KeyMetadata.KeyId), aws.ToString(signKey.KeyMetadata.KeyId), local)
	if err != nil {
		t.Fatal(err)
	}

	a, b := uuid.New(), uuid.New()
	big := bytes.Repeat([]byte("x"), 64<<10) // larger than the KMS message limit
	m1, err := k.TenantMAC(ctx, a, keys.PurposeValueMAC, big)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := k.TenantMAC(ctx, a, keys.PurposeValueMAC, big)
	m3, _ := k.TenantMAC(ctx, b, keys.PurposeValueMAC, big)
	m4, _ := k.TenantMAC(ctx, a, keys.PurposeValueMAC, append(big[:len(big)-1:len(big)-1], 'y'))
	if len(m1) != 32 || !bytes.Equal(m1, m2) || bytes.Equal(m1, m3) || bytes.Equal(m1, m4) {
		t.Fatal("MACs must be deterministic and differ by tenant and data")
	}

	id, sig, err := k.Sign(ctx, []byte("checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(ctx, id, []byte("checkpoint"), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if k.Verify(ctx, id, []byte("checkpoinT"), sig) == nil {
		t.Fatal("altered message verified")
	}
	// Checkpoints signed by the previous (local) keyring still verify.
	oldID, oldSig, _ := local.Sign(ctx, []byte("old"))
	if err := k.Verify(ctx, oldID, []byte("old"), oldSig); err != nil {
		t.Fatalf("fallback verify: %v", err)
	}
}
