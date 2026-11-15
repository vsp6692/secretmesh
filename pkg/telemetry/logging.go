// SPDX-License-Identifier: LicenseRef-SecretMesh-SAL-1.0-DRAFT

// Package telemetry configures structured logging with redaction enabled by default.
package telemetry

import (
	"io"
	"log/slog"
	"strings"
)

const redacted = "[REDACTED]"

// sensitiveKeys are attribute keys whose values are always redacted. A key
// matches when, after lower-casing and replacing '-' with '_', it equals an
// entry or ends with "_" + entry (for example "db_password", "access_token").
var sensitiveKeys = []string{
	"api_key",
	"apikey",
	"authorization",
	"client_secret",
	"authorization_code",
	"code_verifier",
	"cookie",
	"credential",
	"credentials",
	"passwd",
	"password",
	"private_key",
	"secret",
	"secret_value",
	"set_cookie",
	"token",
	"value",
}

// IsSensitiveKey reports whether values logged under key must be redacted.
func IsSensitiveKey(key string) bool {
	k := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	for _, s := range sensitiveKeys {
		if k == s || strings.HasSuffix(k, "_"+s) {
			return true
		}
	}
	return false
}

// NewLogger returns a JSON logger that redacts sensitive attribute keys.
// Values of type sensitive.Value are redacted regardless of key.
func NewLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redactAttr,
	}))
}

func redactAttr(_ []string, a slog.Attr) slog.Attr {
	if IsSensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	return a
}

// ParseLevel converts a level name to a slog.Level, defaulting to Info.
func ParseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}
