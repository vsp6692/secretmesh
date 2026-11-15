// Command secretmesh-api runs the SecretMesh control-plane API.
//
// Usage:
//
//	secretmesh-api serve     run the HTTP server (default), with the worker
//	                         embedded unless SECRETMESH_WORKER=off
//	secretmesh-api worker    run background jobs only
//	secretmesh-api migrate   apply database migrations
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/approvals"
	"github.com/secretmesh/secretmesh/internal/auditexport"
	"github.com/secretmesh/secretmesh/internal/config"
	"github.com/secretmesh/secretmesh/internal/connectors"
	awsconn "github.com/secretmesh/secretmesh/internal/connectors/aws"
	"github.com/secretmesh/secretmesh/internal/connectors/fake"
	"github.com/secretmesh/secretmesh/internal/execution"
	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/keys"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/policy"
	"github.com/secretmesh/secretmesh/internal/rotation"
	"github.com/secretmesh/secretmesh/internal/tenancy"
	"github.com/secretmesh/secretmesh/internal/workflows"
	"github.com/secretmesh/secretmesh/pkg/telemetry"
	"github.com/secretmesh/secretmesh/policies"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "serve":
		err = serve(ctx)
	case "worker":
		err = worker(ctx)
	case "migrate":
		err = migrate(ctx)
	default:
		err = fmt.Errorf("unknown command %q (want serve, worker or migrate)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretmesh-api:", err)
		os.Exit(1)
	}
}

func migrate(ctx context.Context) error {
	cfg, err := config.LoadMigrate()
	if err != nil {
		return err
	}
	logger := telemetry.NewLogger(os.Stdout, telemetry.ParseLevel(cfg.LogLevel))
	if err := postgres.Migrate(ctx, cfg.MigrationsDatabaseURL, logger); err != nil {
		return err
	}
	logger.InfoContext(ctx, "migrations complete")
	return nil
}

func serve(ctx context.Context) error {
	cfg, err := config.LoadServe()
	if err != nil {
		return err
	}
	logger := telemetry.NewLogger(os.Stdout, telemetry.ParseLevel(cfg.LogLevel))

	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.CheckRuntimeRole(ctx, pool); err != nil {
		return fmt.Errorf("SECRETMESH_DATABASE_URL: %w (Row-Level Security would not apply; see deployments/docker/postgres/init.sql)", err)
	}

	tenants := tenancy.NewStore(pool)
	onLogin := []identity.LoginHook{tenancy.AcceptInvitationsHook(tenants)}
	if cfg.Bootstrap.OrgSlug != "" {
		org, err := tenants.EnsureOrganization(ctx, cfg.Bootstrap.OrgSlug, cfg.Bootstrap.OrgName)
		if err != nil {
			return err
		}
		onLogin = append(onLogin, tenancy.BootstrapAdminHook(tenants, org, cfg.Bootstrap.AdminEmail))
		logger.InfoContext(ctx, "bootstrap organization ready", "organization_id", org.ID, "slug", org.Slug)
	}

	gov, err := newGovernance(ctx, pool, cfg.Governance, logger, cfg.Governance.Worker == config.WorkerEmbedded)
	if err != nil {
		return err
	}
	if cfg.Governance.Worker == config.WorkerEmbedded {
		if err := gov.jobs.Start(ctx); err != nil {
			return fmt.Errorf("start worker: %w", err)
		}
		defer stopJobs(gov.jobs, logger)
	}

	identities := identity.NewStore(pool)
	idSvc := identity.NewService(identity.Config{
		Issuer:       cfg.OIDC.Issuer,
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		PublicURL:    cfg.PublicURL,
		CookieSecure: cfg.CookieSecure,
		SessionTTL:   cfg.SessionTTL,

		MFAMethods:          cfg.OIDC.MFAMethods,
		MFAContexts:         cfg.OIDC.MFAContexts,
		AssumeEmailVerified: cfg.OIDC.AssumeEmailVerified,
	}, identities, identity.LoginHooks(onLogin...), logger)

	go purgeExpired(ctx, identities, logger)

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewRouter(httpapi.Deps{
			Pool:       pool,
			Identity:   idSvc,
			Identities: identities,
			Tenancy:    tenants,
			Inventory:  inventory.NewStore(pool),
			Approvals:  gov.approvals,
			Connectors: gov.registry,
			Keyring:    gov.keyring,
			Discovery:  gov.discovery,
			Rotation:   gov.rotation,
			Deliverer:  gov.deliverer,
			Logger:     logger,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() {
		logger.InfoContext(ctx, "api listening", "addr", cfg.HTTPAddr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func worker(ctx context.Context) error {
	cfg, err := config.LoadWorker()
	if err != nil {
		return err
	}
	logger := telemetry.NewLogger(os.Stdout, telemetry.ParseLevel(cfg.LogLevel))
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.CheckRuntimeRole(ctx, pool); err != nil {
		return fmt.Errorf("SECRETMESH_DATABASE_URL: %w", err)
	}
	if cfg.Governance.EnableFakeConnector {
		logger.WarnContext(ctx, "the fake connector keeps state in process memory; a standalone worker cannot see values staged by the API")
	}
	gov, err := newGovernance(ctx, pool, cfg.Governance, logger, true)
	if err != nil {
		return err
	}
	if err := gov.jobs.Start(ctx); err != nil {
		return err
	}
	logger.InfoContext(ctx, "worker started")
	<-ctx.Done()
	stopJobs(gov.jobs, logger)
	return nil
}

type governance struct {
	registry  *connectors.Registry
	keyring   keys.Keyring
	approvals *approvals.Service
	jobs      *workflows.Client
	discovery *inventory.Discovery
	rotation  *rotation.Service
	deliverer *notify.Deliverer
}

// newGovernance builds the approval, execution and job components shared by
// serve and worker.
func newGovernance(ctx context.Context, pool *pgxpool.Pool, cfg config.Governance, logger *slog.Logger, work bool) (*governance, error) {
	if cfg.AWSEndpoint != "" {
		logger.WarnContext(ctx, "AWS endpoint override set; use it only with local emulators", "endpoint", cfg.AWSEndpoint)
	}
	keyring, err := newKeyring(ctx, cfg)
	if err != nil {
		return nil, err
	}
	registry := connectors.NewRegistry()
	if cfg.EnableFakeConnector {
		logger.WarnContext(ctx, "fake connector enabled; never use it in production")
		registry.Register(fake.Provider, fake.New().Factory)
	}
	if cfg.EnableAWSConnector {
		p, err := awsconn.New(ctx, cfg.AWSEndpoint)
		if err != nil {
			return nil, err
		}
		registry.Register(awsconn.ProviderName, p.Factory)
	}
	var exporter *auditexport.Exporter
	if cfg.AuditExport.Bucket != "" {
		if exporter, err = newExporter(ctx, pool, cfg, logger); err != nil {
			return nil, err
		}
	}
	discovery := inventory.NewDiscovery(pool, registry, logger)

	module := policies.Execution
	if cfg.ExecutionPolicyFile != "" {
		if module, err = os.ReadFile(cfg.ExecutionPolicyFile); err != nil {
			return nil, fmt.Errorf("SECRETMESH_EXECUTION_POLICY_FILE: %w", err)
		}
	}
	engine, err := policy.New(ctx, module)
	if err != nil {
		return nil, err
	}

	rotationEngine, err := policy.NewRotation(ctx, policies.Rotation)
	if err != nil {
		return nil, err
	}
	rot := rotation.NewService(pool, registry, rotation.DefaultPlugins(), rotationEngine, logger)
	rot.VerifyTimeout = cfg.RotationVerifyTimeout
	n := cfg.Notifications
	var mail *notify.SMTP
	if n.SMTPAddr != "" {
		mail = &notify.SMTP{Addr: n.SMTPAddr, From: n.SMTPFrom, Username: n.SMTPUsername, Password: n.SMTPPassword, TLS: n.SMTPTLS}
	}
	deliverer := notify.NewDeliverer(pool, registry, mail, &notify.Slack{Prefixes: n.SlackWebhookPrefixes}, n.PublicURL, logger)

	svc := approvals.NewService(pool, registry, keyring, nil, logger)
	svc.TTL = cfg.ChangeRequestTTL
	jobs, err := workflows.New(pool, workflows.Config{
		Work:      work,
		Executor:  execution.NewExecutor(pool, registry, keyring, engine, logger),
		Approvals: svc,
		Registry:  registry,
		Discovery: discovery,
		Exporter:  exporter,
		Rotation:  rot,
		Deliverer: deliverer,
		Keyring:   keyring,
		Logger:    logger,
	})
	if err != nil {
		return nil, fmt.Errorf("job queue: %w", err)
	}
	svc.SetJobs(jobs)
	rot.SetJobs(jobs)
	return &governance{registry: registry, keyring: keyring, approvals: svc, jobs: jobs, discovery: discovery,
		rotation: rot, deliverer: deliverer}, nil
}

// awsConfig loads SecretMesh's own AWS configuration (the default credential
// chain), honoring the emulator endpoint override.
func awsConfig(ctx context.Context, cfg config.Governance, region string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	if cfg.AWSEndpoint != "" {
		opts = append(opts, awsconfig.WithBaseEndpoint(cfg.AWSEndpoint))
	}
	c, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws configuration: %w", err)
	}
	return c, nil
}

func newKeyring(ctx context.Context, cfg config.Governance) (keys.Keyring, error) {
	var local keys.Keyring
	if len(cfg.MasterKey.Reveal()) > 0 {
		k, err := keys.NewLocalKeyring(cfg.MasterKey)
		if err != nil {
			return nil, err
		}
		local = k
	}
	if cfg.Keyring != "aws-kms" {
		if local == nil {
			return nil, errors.New("SECRETMESH_MASTER_KEY is required with the local keyring")
		}
		return local, nil
	}
	c, err := awsConfig(ctx, cfg, "")
	if err != nil {
		return nil, err
	}
	k, err := keys.NewKMSKeyring(ctx, kms.NewFromConfig(c), cfg.KMSMacKeyID, cfg.KMSSigningKeyID, local)
	if err != nil {
		return nil, fmt.Errorf("SECRETMESH_KEYRING=aws-kms: %w", err)
	}
	return k, nil
}

func newExporter(ctx context.Context, pool *pgxpool.Pool, cfg config.Governance, logger *slog.Logger) (*auditexport.Exporter, error) {
	e := cfg.AuditExport
	c, err := awsConfig(ctx, cfg, e.Region)
	if err != nil {
		return nil, err
	}
	if e.RoleARN != "" {
		c.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(c), e.RoleARN,
			func(o *stscreds.AssumeRoleOptions) { o.RoleSessionName = "secretmesh-audit-export" }))
	}
	client := s3.NewFromConfig(c, func(o *s3.Options) { o.UsePathStyle = cfg.AWSEndpoint != "" })
	store, err := auditexport.NewS3(ctx, client, e.Bucket, e.Prefix, e.Mode)
	if err != nil {
		return nil, fmt.Errorf("SECRETMESH_AUDIT_EXPORT_BUCKET: %w", err)
	}
	return auditexport.New(pool, store, time.Duration(e.RetentionDays)*24*time.Hour, logger), nil
}

func stopJobs(j *workflows.Client, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := j.Stop(ctx); err != nil {
		logger.Warn("stop worker", "error", err)
	}
}

func purgeExpired(ctx context.Context, s *identity.Store, logger *slog.Logger) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
				logger.WarnContext(ctx, "purge expired sessions", "error", err)
			}
		}
	}
}
