package keys

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

func TestLocalKeyring(t *testing.T) {
	ctx := context.Background()
	k, err := NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	a, b := uuid.New(), uuid.New()

	m1, _ := k.TenantMAC(ctx, a, PurposeValueMAC, []byte("v"))
	m2, _ := k.TenantMAC(ctx, a, PurposeValueMAC, []byte("v"))
	m3, _ := k.TenantMAC(ctx, b, PurposeValueMAC, []byte("v"))
	m4, _ := k.TenantMAC(ctx, a, "other", []byte("v"))
	if !bytes.Equal(m1, m2) || bytes.Equal(m1, m3) || bytes.Equal(m1, m4) {
		t.Fatal("MAC keys must be deterministic and separated by tenant and purpose")
	}
	if _, err := k.TenantMAC(ctx, uuid.Nil, PurposeValueMAC, nil); err == nil {
		t.Fatal("nil tenant accepted")
	}

	id, sig, _ := k.Sign(ctx, []byte("msg"))
	if err := k.Verify(ctx, id, []byte("msg"), sig); err != nil {
		t.Fatal(err)
	}
	if k.Verify(ctx, id, []byte("msG"), sig) == nil || k.Verify(ctx, "other", []byte("msg"), sig) == nil {
		t.Fatal("forged signature accepted")
	}

	other, _ := NewLocalKeyring(sensitive.New(bytes.Repeat([]byte{8}, 32)))
	if other.Verify(ctx, id, []byte("msg"), sig) == nil {
		t.Fatal("signature verified under a different master key")
	}
	if _, err := NewLocalKeyring(sensitive.New([]byte("short"))); err == nil {
		t.Fatal("short master key accepted")
	}
}
