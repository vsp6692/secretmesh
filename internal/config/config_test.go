// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setBase(t *testing.T) {
	// Isolate from the developer's environment (e.g. an exported .env).
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "SECRETMESH_") {
			t.Setenv(k, "")
		}
	}
	t.Setenv("SECRETMESH_PUBLIC_URL", "https://secretmesh.example.com/")
	t.Setenv("SECRETMESH_DATABASE_URL", "postgres://app@db/secretmesh")
	t.Setenv("SECRETMESH_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("SECRETMESH_OIDC_CLIENT_ID", "secretmesh")
	t.Setenv("SECRETMESH_OIDC_CLIENT_SECRET", "s3cr3t")
	t.Setenv("SECRETMESH_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
}

func TestLoadServeDefaults(t *testing.T) {
	setBase(t)
	c, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	if !c.CookieSecure {
		t.Error("cookies must be Secure by default")
	}
	if c.PublicURL.String() != "https://secretmesh.example.com" {
		t.Errorf("PublicURL = %q, trailing slash should be trimmed", c.PublicURL)
	}
	if c.OIDC.ClientSecret.RevealString() != "s3cr3t" {
		t.Error("client secret not loaded")
	}
}

func TestLoadServeRejectsInsecureCookiesOverHTTPS(t *testing.T) {
	setBase(t)
	t.Setenv("SECRETMESH_COOKIE_SECURE", "false")
	if _, err := LoadServe(); err == nil || !strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("expected cookie error, got %v", err)
	}
}

func TestLoadServeBootstrapValidation(t *testing.T) {
	setBase(t)
	t.Setenv("SECRETMESH_BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
	if _, err := LoadServe(); err == nil {
		t.Fatal("admin email without bootstrap org must be rejected")
	}
}

func TestSecretFromFile(t *testing.T) {
	setBase(t)
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETMESH_OIDC_CLIENT_SECRET", "")
	t.Setenv("SECRETMESH_OIDC_CLIENT_SECRET_FILE", path)

	c, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.ClientSecret.RevealString() != "from-file" {
		t.Errorf("got %q", c.OIDC.ClientSecret.RevealString())
	}

	t.Setenv("SECRETMESH_OIDC_CLIENT_SECRET", "also-set")
	if _, err := LoadServe(); err == nil {
		t.Fatal("setting both value and _FILE must be rejected")
	}
}

func TestErrorsNeverContainSecrets(t *testing.T) {
	setBase(t)
	t.Setenv("SECRETMESH_PUBLIC_URL", "")
	_, err := LoadServe()
	if err == nil || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "postgres://") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOIDCMFAAndEmailSettings(t *testing.T) {
	setBase(t)
	c, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.OIDC.MFAMethods, ",") != "mfa,otp,hwk" || c.OIDC.AssumeEmailVerified {
		t.Fatalf("unexpected defaults: %+v", c.OIDC)
	}

	t.Setenv("SECRETMESH_OIDC_MFA_ACR", " gold, ,silver ")
	if c, err = LoadServe(); err != nil || strings.Join(c.OIDC.MFAContexts, ",") != "gold,silver" {
		t.Fatalf("acr list: %v %v", c.OIDC.MFAContexts, err)
	}

	t.Setenv("SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED", "true")
	t.Setenv("SECRETMESH_OIDC_ISSUER", "https://login.microsoftonline.com/0b5b6f9e-0000-0000-0000-000000000000/v2.0")
	if _, err := LoadServe(); err != nil {
		t.Fatalf("single-tenant issuer must be allowed: %v", err)
	}
	for _, iss := range []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations",
	} {
		t.Setenv("SECRETMESH_OIDC_ISSUER", iss)
		if _, err := LoadServe(); err == nil {
			t.Errorf("%s: multi-tenant issuer must be rejected", iss)
		}
	}
}

func TestGovernanceSettings(t *testing.T) {
	setBase(t)
	c, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	g := c.Governance
	if len(g.MasterKey.Reveal()) != 32 || g.Worker != WorkerEmbedded || g.EnableFakeConnector || g.ChangeRequestTTL != 72*time.Hour {
		t.Fatalf("unexpected defaults: %+v", g)
	}
	for _, bad := range []string{"", "c2hvcnQ=", "not base64!"} {
		t.Setenv("SECRETMESH_MASTER_KEY", bad)
		if _, err := LoadServe(); err == nil || strings.Contains(err.Error(), bad+"\n") {
			t.Errorf("master key %q accepted", bad)
		}
	}
	t.Setenv("SECRETMESH_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("SECRETMESH_WORKER", "sometimes")
	if _, err := LoadServe(); err == nil {
		t.Error("invalid worker mode accepted")
	}
	t.Setenv("SECRETMESH_WORKER", "")

	// KMS keyring: key IDs required, master key optional.
	t.Setenv("SECRETMESH_KEYRING", "aws-kms")
	if _, err := LoadServe(); err == nil {
		t.Error("aws-kms without key IDs accepted")
	}
	t.Setenv("SECRETMESH_KMS_MAC_KEY_ID", "alias/mac")
	t.Setenv("SECRETMESH_KMS_SIGNING_KEY_ID", "alias/sign")
	t.Setenv("SECRETMESH_MASTER_KEY", "")
	if _, err := LoadServe(); err != nil {
		t.Errorf("aws-kms without master key: %v", err)
	}
	t.Setenv("SECRETMESH_AUDIT_EXPORT_BUCKET", "audit")
	if _, err := LoadServe(); err == nil {
		t.Error("export bucket without region accepted")
	}
}

func TestNotificationSettings(t *testing.T) {
	setBase(t)
	c, err := LoadServe()
	if err != nil {
		t.Fatal(err)
	}
	n := c.Governance.Notifications
	if n.SMTPAddr != "" || n.SMTPTLS != "starttls" || len(n.SlackWebhookPrefixes) != 1 || n.SlackWebhookPrefixes[0] != "https://hooks.slack.com/" ||
		c.Governance.RotationVerifyTimeout != 30*time.Minute {
		t.Fatalf("unexpected defaults: %+v %v", n, c.Governance.RotationVerifyTimeout)
	}

	t.Setenv("SECRETMESH_SMTP_ADDR", "smtp.example.com:587")
	t.Setenv("SECRETMESH_SMTP_FROM", "SecretMesh <secretmesh@example.com>")
	t.Setenv("SECRETMESH_SMTP_PASSWORD", "smtp-pass-123")
	c, err = LoadServe()
	if err != nil || c.Governance.Notifications.SMTPPassword.RevealString() != "smtp-pass-123" {
		t.Fatalf("smtp: %v", err)
	}
	for name, kv := range map[string][2]string{
		"plaintext to a remote server": {"SECRETMESH_SMTP_TLS", "none"},
		"unknown TLS mode":             {"SECRETMESH_SMTP_TLS", "maybe"},
		"bad sender":                   {"SECRETMESH_SMTP_FROM", "not an address"},
		"bad address":                  {"SECRETMESH_SMTP_ADDR", "smtp.example.com"},
		"http webhook prefix":          {"SECRETMESH_SLACK_WEBHOOK_PREFIXES", "http://hooks.example.com/"},
		"prefix without path":          {"SECRETMESH_SLACK_WEBHOOK_PREFIXES", "https://hooks.slack.com"},
		"short verify timeout":         {"SECRETMESH_ROTATION_VERIFY_TIMEOUT", "1s"},
	} {
		old := os.Getenv(kv[0])
		t.Setenv(kv[0], kv[1])
		_, err := LoadServe()
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if strings.Contains(err.Error(), "smtp-pass-123") {
			t.Errorf("%s: error contains the SMTP password", name)
		}
		t.Setenv(kv[0], old)
	}
	t.Setenv("SECRETMESH_SMTP_ADDR", "127.0.0.1:1025")
	t.Setenv("SECRETMESH_SMTP_TLS", "none")
	t.Setenv("SECRETMESH_SLACK_WEBHOOK_PREFIXES", "https://hooks.slack.com/, http://127.0.0.1:9999/")
	if c, err := LoadServe(); err != nil || len(c.Governance.Notifications.SlackWebhookPrefixes) != 2 {
		t.Fatalf("loopback settings rejected: %v", err)
	}
}
