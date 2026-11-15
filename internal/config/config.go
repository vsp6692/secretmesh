// Package config loads SecretMesh configuration from the environment.
//
// Any setting holding credentials also accepts a <NAME>_FILE variant that
// points to a file (for Kubernetes secrets and Docker secrets).
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

type Config struct {
	HTTPAddr string
	LogLevel string

	// PublicURL is the browser-facing origin (the web app), e.g. http://localhost:3000.
	PublicURL *url.URL

	// DatabaseURL connects as the application role (no BYPASSRLS, no DDL).
	DatabaseURL sensitive.Value
	// MigrationsDatabaseURL connects as the schema owner; only used by `migrate`.
	MigrationsDatabaseURL sensitive.Value

	OIDC OIDC

	CookieSecure bool
	SessionTTL   time.Duration

	Bootstrap Bootstrap

	Governance Governance
}

// WorkerMode selects where background jobs run.
type WorkerMode string

const (
	// WorkerEmbedded runs jobs inside the API process (default).
	WorkerEmbedded WorkerMode = "embedded"
	// WorkerOff only enqueues; run `secretmesh-api worker` separately.
	WorkerOff WorkerMode = "off"
)

// Governance configures approvals, execution and audit.
type Governance struct {
	// MasterKey derives approval MAC keys and the audit signing key (ADR-0009).
	MasterKey sensitive.Value
	// EnableFakeConnector enables the in-memory provider (development only).
	EnableFakeConnector bool
	Worker              WorkerMode
	// ExecutionPolicyFile replaces the built-in execution policy.
	ExecutionPolicyFile string
	ChangeRequestTTL    time.Duration

	// EnableAWSConnector registers the AWS Secrets Manager provider.
	EnableAWSConnector bool
	// AWSEndpoint overrides AWS endpoints (local emulators only).
	AWSEndpoint string

	// Keyring is "local" (keys derived from MasterKey) or "aws-kms".
	Keyring         string
	KMSMacKeyID     string
	KMSSigningKeyID string

	AuditExport AuditExport

	Notifications Notifications
	// RotationVerifyTimeout bounds how long a provider rotation may run.
	RotationVerifyTimeout time.Duration
}

// Notifications configures delivery. Email is disabled without SMTPAddr.
type Notifications struct {
	SMTPAddr     string
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword sensitive.Value
	// SMTPTLS is starttls (default), tls or none (loopback hosts only).
	SMTPTLS string
	// SlackWebhookPrefixes limit which URLs Slack channels may post to.
	SlackWebhookPrefixes []string
	// PublicURL is used for links in notifications.
	PublicURL string
}

// AuditExport configures copies of the audit log to S3 Object Lock.
// Disabled when Bucket is empty.
type AuditExport struct {
	Bucket        string
	Region        string
	Prefix        string
	Mode          string // COMPLIANCE or GOVERNANCE
	RetentionDays int
	// RoleARN, if set, is assumed for writing, so audit storage permissions
	// stay separate from SecretMesh's other permissions.
	RoleARN string
}

type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret sensitive.Value
	// MFAMethods are ID token "amr" values (RFC 8176) that count as MFA.
	MFAMethods []string
	// MFAContexts are ID token "acr" values that count as MFA.
	MFAContexts []string
	// AssumeEmailVerified treats a missing email_verified claim as true.
	AssumeEmailVerified bool
}

// DefaultMFAMethods are the RFC 8176 "amr" values accepted as MFA by default.
var DefaultMFAMethods = []string{"mfa", "otp", "hwk"}

// Bootstrap creates an initial organization for self-hosted installations and
// grants org_admin to the user whose verified email matches AdminEmail.
type Bootstrap struct {
	OrgSlug    string
	OrgName    string
	AdminEmail string
}

// LoadServe loads configuration required by the API server.
func LoadServe() (*Config, error) {
	var errs []error
	c := &Config{
		HTTPAddr:     getenv("SECRETMESH_HTTP_ADDR", ":8080"),
		LogLevel:     getenv("SECRETMESH_LOG_LEVEL", "info"),
		CookieSecure: true,
		SessionTTL:   12 * time.Hour,
		Bootstrap: Bootstrap{
			OrgSlug:    os.Getenv("SECRETMESH_BOOTSTRAP_ORG_SLUG"),
			OrgName:    os.Getenv("SECRETMESH_BOOTSTRAP_ORG_NAME"),
			AdminEmail: os.Getenv("SECRETMESH_BOOTSTRAP_ADMIN_EMAIL"),
		},
	}

	publicURL := os.Getenv("SECRETMESH_PUBLIC_URL")
	if publicURL == "" {
		errs = append(errs, errors.New("SECRETMESH_PUBLIC_URL is required"))
	} else if u, err := url.Parse(publicURL); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("SECRETMESH_PUBLIC_URL must be an absolute URL"))
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/")
		c.PublicURL = u
	}

	var err error
	if c.DatabaseURL, err = requiredSecret("SECRETMESH_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	}

	c.OIDC.Issuer = os.Getenv("SECRETMESH_OIDC_ISSUER")
	c.OIDC.ClientID = os.Getenv("SECRETMESH_OIDC_CLIENT_ID")
	if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("SECRETMESH_OIDC_ISSUER and SECRETMESH_OIDC_CLIENT_ID are required"))
	}
	if c.OIDC.ClientSecret, err = requiredSecret("SECRETMESH_OIDC_CLIENT_SECRET"); err != nil {
		errs = append(errs, err)
	}

	c.OIDC.MFAMethods = list(getenv("SECRETMESH_OIDC_MFA_AMR", strings.Join(DefaultMFAMethods, ",")))
	c.OIDC.MFAContexts = list(os.Getenv("SECRETMESH_OIDC_MFA_ACR"))
	if v := os.Getenv("SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED"); v != "" {
		if c.OIDC.AssumeEmailVerified, err = strconv.ParseBool(v); err != nil {
			errs = append(errs, fmt.Errorf("SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED: %w", err))
		}
	}
	if c.OIDC.AssumeEmailVerified && multiTenantIssuer(c.OIDC.Issuer) {
		errs = append(errs, errors.New("SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED is not allowed with a multi-tenant issuer; use a tenant-specific issuer"))
	}

	if v := os.Getenv("SECRETMESH_COOKIE_SECURE"); v != "" {
		if c.CookieSecure, err = strconv.ParseBool(v); err != nil {
			errs = append(errs, fmt.Errorf("SECRETMESH_COOKIE_SECURE: %w", err))
		}
	}
	if c.PublicURL != nil && c.PublicURL.Scheme == "https" && !c.CookieSecure {
		errs = append(errs, errors.New("SECRETMESH_COOKIE_SECURE=false is only allowed with an http:// public URL"))
	}

	if v := os.Getenv("SECRETMESH_SESSION_TTL"); v != "" {
		if c.SessionTTL, err = time.ParseDuration(v); err != nil || c.SessionTTL <= 0 {
			errs = append(errs, fmt.Errorf("SECRETMESH_SESSION_TTL must be a positive duration"))
		}
	}

	c.Governance, err = loadGovernance()
	if err != nil {
		errs = append(errs, err)
	}

	if (c.Bootstrap.OrgSlug == "") != (c.Bootstrap.OrgName == "") {
		errs = append(errs, errors.New("SECRETMESH_BOOTSTRAP_ORG_SLUG and SECRETMESH_BOOTSTRAP_ORG_NAME must be set together"))
	}
	if c.Bootstrap.AdminEmail != "" && c.Bootstrap.OrgSlug == "" {
		errs = append(errs, errors.New("SECRETMESH_BOOTSTRAP_ADMIN_EMAIL requires a bootstrap organization"))
	}

	return c, errors.Join(errs...)
}

// LoadWorker loads configuration required by the standalone worker.
func LoadWorker() (*Config, error) {
	var errs []error
	c := &Config{LogLevel: getenv("SECRETMESH_LOG_LEVEL", "info")}
	var err error
	if c.DatabaseURL, err = requiredSecret("SECRETMESH_DATABASE_URL"); err != nil {
		errs = append(errs, err)
	}
	if c.Governance, err = loadGovernance(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

func loadGovernance() (Governance, error) {
	var errs []error
	g := Governance{
		Worker:              WorkerMode(getenv("SECRETMESH_WORKER", string(WorkerEmbedded))),
		ExecutionPolicyFile: os.Getenv("SECRETMESH_EXECUTION_POLICY_FILE"),
		ChangeRequestTTL:    72 * time.Hour,
		EnableAWSConnector:  true,
		AWSEndpoint:         os.Getenv("SECRETMESH_AWS_ENDPOINT_URL"),
		Keyring:             getenv("SECRETMESH_KEYRING", "local"),
		KMSMacKeyID:         os.Getenv("SECRETMESH_KMS_MAC_KEY_ID"),
		KMSSigningKeyID:     os.Getenv("SECRETMESH_KMS_SIGNING_KEY_ID"),
		AuditExport: AuditExport{
			Bucket:        os.Getenv("SECRETMESH_AUDIT_EXPORT_BUCKET"),
			Region:        os.Getenv("SECRETMESH_AUDIT_EXPORT_REGION"),
			Prefix:        getenv("SECRETMESH_AUDIT_EXPORT_PREFIX", "secretmesh-audit"),
			Mode:          getenv("SECRETMESH_AUDIT_EXPORT_MODE", "COMPLIANCE"),
			RetentionDays: 365,
			RoleARN:       os.Getenv("SECRETMESH_AUDIT_EXPORT_ROLE_ARN"),
		},
	}
	switch g.Keyring {
	case "local":
	case "aws-kms":
		if g.KMSMacKeyID == "" || g.KMSSigningKeyID == "" {
			errs = append(errs, errors.New("SECRETMESH_KEYRING=aws-kms needs SECRETMESH_KMS_MAC_KEY_ID and SECRETMESH_KMS_SIGNING_KEY_ID"))
		}
	default:
		errs = append(errs, errors.New("SECRETMESH_KEYRING must be local or aws-kms"))
	}
	// With aws-kms the master key is optional and only verifies checkpoints
	// signed before the switch.
	if raw, err := requiredSecret("SECRETMESH_MASTER_KEY"); err != nil {
		if g.Keyring == "local" {
			errs = append(errs, err)
		}
	} else if key, err := base64.StdEncoding.DecodeString(raw.RevealString()); err != nil || len(key) != 32 {
		errs = append(errs, errors.New("SECRETMESH_MASTER_KEY must be 32 random bytes, base64-encoded (openssl rand -base64 32)"))
	} else {
		g.MasterKey = sensitive.New(key)
	}
	if v := os.Getenv("SECRETMESH_ENABLE_AWS_CONNECTOR"); v != "" {
		var err error
		if g.EnableAWSConnector, err = strconv.ParseBool(v); err != nil {
			errs = append(errs, fmt.Errorf("SECRETMESH_ENABLE_AWS_CONNECTOR: %w", err))
		}
	}
	if v := os.Getenv("SECRETMESH_AUDIT_EXPORT_RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 36500 {
			errs = append(errs, errors.New("SECRETMESH_AUDIT_EXPORT_RETENTION_DAYS must be 1-36500"))
		}
		g.AuditExport.RetentionDays = n
	}
	if g.AuditExport.Bucket != "" && g.AuditExport.Region == "" {
		errs = append(errs, errors.New("SECRETMESH_AUDIT_EXPORT_REGION is required with SECRETMESH_AUDIT_EXPORT_BUCKET"))
	}
	if v := os.Getenv("SECRETMESH_ENABLE_FAKE_CONNECTOR"); v != "" {
		var err error
		if g.EnableFakeConnector, err = strconv.ParseBool(v); err != nil {
			errs = append(errs, fmt.Errorf("SECRETMESH_ENABLE_FAKE_CONNECTOR: %w", err))
		}
	}
	if g.Worker != WorkerEmbedded && g.Worker != WorkerOff {
		errs = append(errs, errors.New("SECRETMESH_WORKER must be embedded or off"))
	}
	g.RotationVerifyTimeout = 30 * time.Minute
	if v := os.Getenv("SECRETMESH_ROTATION_VERIFY_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			errs = append(errs, errors.New("SECRETMESH_ROTATION_VERIFY_TIMEOUT must be a duration between 1m and 24h"))
		}
		g.RotationVerifyTimeout = d
	}
	n, err := loadNotifications()
	if err != nil {
		errs = append(errs, err)
	}
	g.Notifications = n
	if v := os.Getenv("SECRETMESH_CHANGE_REQUEST_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			errs = append(errs, errors.New("SECRETMESH_CHANGE_REQUEST_TTL must be a duration between 1m and 720h"))
		}
		g.ChangeRequestTTL = d
	}
	return g, errors.Join(errs...)
}

func loadNotifications() (Notifications, error) {
	var errs []error
	n := Notifications{
		SMTPAddr:             os.Getenv("SECRETMESH_SMTP_ADDR"),
		SMTPFrom:             os.Getenv("SECRETMESH_SMTP_FROM"),
		SMTPUsername:         os.Getenv("SECRETMESH_SMTP_USERNAME"),
		SMTPTLS:              getenv("SECRETMESH_SMTP_TLS", "starttls"),
		SlackWebhookPrefixes: list(getenv("SECRETMESH_SLACK_WEBHOOK_PREFIXES", "https://hooks.slack.com/")),
		PublicURL:            os.Getenv("SECRETMESH_PUBLIC_URL"),
	}
	if os.Getenv("SECRETMESH_SMTP_PASSWORD") != "" || os.Getenv("SECRETMESH_SMTP_PASSWORD_FILE") != "" {
		p, err := requiredSecret("SECRETMESH_SMTP_PASSWORD")
		if err != nil {
			errs = append(errs, err)
		}
		n.SMTPPassword = p
	}
	if n.SMTPAddr != "" {
		host, _, err := net.SplitHostPort(n.SMTPAddr)
		if err != nil {
			errs = append(errs, errors.New("SECRETMESH_SMTP_ADDR must be host:port"))
		}
		if _, err := mail.ParseAddress(n.SMTPFrom); err != nil {
			errs = append(errs, errors.New("SECRETMESH_SMTP_FROM must be an email address"))
		}
		switch n.SMTPTLS {
		case "starttls", "tls":
		case "none":
			if !loopback(host) {
				errs = append(errs, errors.New("SECRETMESH_SMTP_TLS=none is only allowed for a loopback SMTP server"))
			}
		default:
			errs = append(errs, errors.New("SECRETMESH_SMTP_TLS must be starttls, tls or none"))
		}
	}
	for _, p := range n.SlackWebhookPrefixes {
		u, err := url.Parse(p)
		if err != nil || !strings.HasSuffix(p, "/") || u.Host == "" ||
			(u.Scheme != "https" && (u.Scheme != "http" || !loopback(u.Hostname()))) {
			errs = append(errs, fmt.Errorf("SECRETMESH_SLACK_WEBHOOK_PREFIXES: %q must be an https URL prefix ending in /", p))
		}
	}
	return n, errors.Join(errs...)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// LoadMigrate loads configuration required by the migrate command.
func LoadMigrate() (*Config, error) {
	u, err := requiredSecret("SECRETMESH_MIGRATIONS_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	return &Config{
		LogLevel:              getenv("SECRETMESH_LOG_LEVEL", "info"),
		MigrationsDatabaseURL: u,
	}, nil
}

// multiTenantIssuer reports Microsoft Entra issuers that accept any tenant,
// where users can control their own email attribute.
func multiTenantIssuer(issuer string) bool {
	for _, t := range []string{"/common/", "/organizations/", "/consumers/"} {
		if strings.Contains(strings.ToLower(issuer)+"/", t) {
			return true
		}
	}
	return false
}

// list splits a comma-separated value, dropping empty items.
func list(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// requiredSecret reads key, or the file named by key_FILE.
func requiredSecret(key string) (sensitive.Value, error) {
	v := os.Getenv(key)
	path := os.Getenv(key + "_FILE")
	switch {
	case v != "" && path != "":
		return sensitive.Value{}, fmt.Errorf("set only one of %s and %s_FILE", key, key)
	case v != "":
		return sensitive.FromString(v), nil
	case path != "":
		b, err := os.ReadFile(path) //nolint:gosec // path is operator-supplied configuration
		if err != nil {
			return sensitive.Value{}, fmt.Errorf("%s_FILE: %w", key, err)
		}
		return sensitive.New([]byte(strings.TrimSpace(string(b)))), nil
	default:
		return sensitive.Value{}, fmt.Errorf("%s (or %s_FILE) is required", key, key)
	}
}
