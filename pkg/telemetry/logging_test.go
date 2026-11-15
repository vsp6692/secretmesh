package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	sensitive := []string{"password", "DB_PASSWORD", "access_token", "Authorization", "set-cookie", "client_secret", "value", "secret", "authorization_code"}
	safe := []string{"secret_id", "token_type", "request_id", "path", "status", "provider_version_id", "error_code"}

	for _, k := range sensitive {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range safe {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestLoggerRedactsNestedKeys(t *testing.T) {
	var buf bytes.Buffer
	NewLogger(&buf, slog.LevelDebug).Info("login",
		"user", "alice",
		slog.Group("request", "authorization", "Bearer abc123", "path", "/api/v1/me"),
		"client_secret", "s3cr3t",
	)

	out := buf.String()
	for _, leaked := range []string{"abc123", "s3cr3t"} {
		if strings.Contains(out, leaked) {
			t.Errorf("log leaked %q: %s", leaked, out)
		}
	}
	for _, kept := range []string{"alice", "/api/v1/me"} {
		if !strings.Contains(out, kept) {
			t.Errorf("log dropped %q: %s", kept, out)
		}
	}
}
