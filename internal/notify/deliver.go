package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/pkg/sensitive"
)

// MaxAttempts per delivery; retries back off exponentially from 30 seconds.
const MaxAttempts = 5

// SMTP is deployment-level mail configuration.
type SMTP struct {
	Addr     string // host:port
	From     string
	Username string
	Password sensitive.Value
	// TLS is "starttls" (required STARTTLS), "tls" (implicit TLS) or "none"
	// (development only).
	TLS string
}

func (s *SMTP) Configured() bool { return s != nil && s.Addr != "" }

// Send delivers one plain-text message to one recipient.
func (s *SMTP) Send(ctx context.Context, to, subject, body string) error {
	rcpt, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	d := &net.Dialer{}
	var conn net.Conn
	if s.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", s.Addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", s.Addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if s.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not offer STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.Username != "" {
		// net/smtp refuses PLAIN auth without TLS except to localhost.
		if err := c.Auth(smtp.PlainAuth("", s.Username, string(s.Password.Reveal()), host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(message(from, rcpt, subject, body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func message(from, to *mail.Address, subject, body string) []byte {
	var b bytes.Buffer
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n",
		from.String(), to.String(), mime.QEncoding.Encode("utf-8", oneLine(subject, 200)),
		time.Now().UTC().Format(time.RFC1123Z), hex.EncodeToString(id), domain)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}

// Slack posts to incoming webhooks. Webhook URLs must start with one of
// Prefixes, so a channel cannot make SecretMesh call arbitrary hosts.
type Slack struct {
	Prefixes []string
	Client   *http.Client
}

// DefaultSlackPrefixes allows only Slack's webhook host.
var DefaultSlackPrefixes = []string{"https://hooks.slack.com/"}

var errWebhookNotAllowed = errors.New("webhook URL is not an allowed Slack webhook")

func (s *Slack) Send(ctx context.Context, webhook sensitive.Value, text string) error {
	u := strings.TrimSpace(string(webhook.Reveal()))
	allowed := false
	for _, p := range s.Prefixes {
		if strings.HasPrefix(u, p) {
			allowed = true
		}
	}
	if !allowed {
		return errWebhookNotAllowed
	}
	body, _ := json.Marshal(map[string]string{"text": text})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	client := s.Client
	if client == nil {
		client = &http.Client{
			// Never follow redirects away from the allowed host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	res, err := client.Do(req)
	if err != nil {
		// The error text contains the URL, which is the credential.
		return errors.New("webhook request failed")
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("webhook returned HTTP %d", res.StatusCode)
	}
	return nil
}

// Deliverer sends pending deliveries.
type Deliverer struct {
	pool      *pgxpool.Pool
	registry  *connectors.Registry
	smtp      *SMTP
	slack     *Slack
	publicURL string
	logger    *slog.Logger
}

func NewDeliverer(pool *pgxpool.Pool, registry *connectors.Registry, smtpCfg *SMTP, slack *Slack, publicURL string, logger *slog.Logger) *Deliverer {
	if slack == nil {
		slack = &Slack{Prefixes: DefaultSlackPrefixes}
	}
	return &Deliverer{pool: pool, registry: registry, smtp: smtpCfg, slack: slack,
		publicURL: strings.TrimRight(publicURL, "/"), logger: logger}
}

// EmailConfigured reports whether email channels can deliver.
func (d *Deliverer) EmailConfigured() bool { return d.smtp.Configured() }

// DeliverDue sends up to 100 due deliveries and returns how many were sent.
func (d *Deliverer) DeliverDue(ctx context.Context) (int, error) {
	rows, err := d.pool.Query(ctx, `SELECT organization_id, notification_id, channel_id FROM secretmesh_notification_deliveries_due(100)`)
	if err != nil {
		return 0, err
	}
	type item struct{ org, n, c uuid.UUID }
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (item, error) {
		var i item
		return i, r.Scan(&i.org, &i.n, &i.c)
	})
	if err != nil {
		return 0, err
	}
	sent := 0
	var errs []error
	for _, it := range items {
		ok, err := d.deliver(ctx, it.org, it.n, it.c)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			sent++
		}
	}
	return sent, errors.Join(errs...)
}

// deliver sends one delivery while holding its row lock, so concurrent
// workers never send it twice.
func (d *Deliverer) deliver(ctx context.Context, org, notificationID, channelID uuid.UUID) (bool, error) {
	ctx = postgres.WithScope(ctx, postgres.Scope{OrganizationID: org})
	sent := false
	err := postgres.Tx(ctx, d.pool, func(tx pgx.Tx) error {
		var attempts int
		err := tx.QueryRow(ctx, `SELECT attempts FROM notification_deliveries
			WHERE organization_id = $1 AND notification_id = $2 AND channel_id = $3 AND status = 'pending'
			FOR UPDATE SKIP LOCKED`, org, notificationID, channelID).Scan(&attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var subject, body, link string
		var recipients []uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT subject, body, link_path, recipients FROM notifications
			WHERE organization_id = $1 AND id = $2`, org, notificationID).Scan(&subject, &body, &link, &recipients); err != nil {
			return err
		}
		ch, err := ChannelTx(ctx, tx, org, channelID)
		if err != nil {
			return err
		}
		if link != "" {
			body += "\n\n" + d.publicURL + link
		}

		var sendErr error
		switch {
		case !ch.Enabled:
			sendErr = permanent("channel disabled")
		case ch.Kind == KindEmail:
			sendErr = d.email(ctx, tx, recipients, subject, body)
		case ch.Kind == KindSlack:
			sendErr = d.slackSend(ctx, tx, org, ch, "*"+subject+"*\n"+body)
		default:
			sendErr = permanent("unknown channel kind")
		}

		if sendErr == nil {
			sent = true
			_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET status = 'sent', attempts = attempts + 1, sent_at = now(),
				last_error = NULL WHERE organization_id = $1 AND notification_id = $2 AND channel_id = $3`, org, notificationID, channelID)
			return err
		}
		attempts++
		status, next := "pending", time.Duration(30<<min(attempts-1, 10))*time.Second
		var p permanentError
		if attempts >= MaxAttempts || errors.As(sendErr, &p) {
			status = "failed"
		}
		d.logger.WarnContext(ctx, "notification delivery failed", "organization_id", org, "notification_id", notificationID,
			"channel", ch.Name, "attempt", attempts, "final", status == "failed", "error", sendErr)
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET status = $4, attempts = $5, last_error = $6,
			next_attempt_at = now() + $7::interval WHERE organization_id = $1 AND notification_id = $2 AND channel_id = $3`,
			org, notificationID, channelID, status, attempts, oneLine(sendErr.Error(), 300), next)
		return err
	})
	return sent, err
}

func (d *Deliverer) email(ctx context.Context, tx pgx.Tx, recipients []uuid.UUID, subject, body string) error {
	if !d.smtp.Configured() {
		return permanent("email is not configured (SECRETMESH_SMTP_ADDR)")
	}
	rows, err := tx.Query(ctx, `SELECT email FROM users WHERE id = ANY($1) AND status = 'active' ORDER BY email`, recipients)
	if err != nil {
		return err
	}
	emails, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	// One message per recipient keeps addresses private. A partial failure
	// retries everyone; duplicates are preferable to lost alerts.
	for _, to := range emails {
		if err := d.smtp.Send(ctx, to, subject, body); err != nil {
			return fmt.Errorf("send to recipient: %w", err)
		}
	}
	return nil
}

func (d *Deliverer) slackSend(ctx context.Context, tx pgx.Tx, org uuid.UUID, ch Channel, text string) error {
	s, err := inventory.SecretTx(ctx, tx, org, ch.WebhookSecretID)
	if errors.Is(err, inventory.ErrNotFound) {
		return permanent("webhook secret not found")
	}
	if err != nil {
		return err
	}
	if s.Status != "active" {
		return permanent("webhook secret deleted")
	}
	conn, err := inventory.ConnectionTx(ctx, tx, org, s.ConnectionID)
	if err != nil {
		return err
	}
	store, err := d.registry.Store(connectors.Connection{ID: conn.ID, OrganizationID: org, Provider: conn.Provider, Config: conn.Config})
	if err != nil {
		return permanent("webhook secret's provider is unavailable")
	}
	url, _, err := store.Reveal(ctx, connectors.Target{ConnectionID: conn.ID, Name: s.Name, ProviderRef: s.ProviderRef})
	if err != nil {
		return fmt.Errorf("read webhook secret: %w", err)
	}
	defer url.Wipe()
	err = d.slack.Send(ctx, url, text)
	if errors.Is(err, errWebhookNotAllowed) {
		return permanent(err.Error())
	}
	return err
}

type permanentError struct{ msg string }

func (p permanentError) Error() string { return p.msg }

func permanent(msg string) error { return permanentError{msg} }
