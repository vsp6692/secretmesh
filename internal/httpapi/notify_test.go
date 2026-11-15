package httpapi_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/secretmesh/secretmesh/internal/httpapi"
	"github.com/secretmesh/secretmesh/internal/identity/oidctest"
)

func (g *gov) deliver(t *testing.T) int {
	t.Helper()
	n, err := g.deliverer.DeliverDue(context.Background())
	if err != nil {
		t.Logf("deliver: %v", err)
	}
	return n
}

func TestNotificationDelivery(t *testing.T) {
	g := newGov(t)
	secClaims := oidctest.Claims{Subject: "u-sec", Email: "sec@example.com", EmailVerified: true}
	sec, secID := g.person(t, secClaims, "member")
	g.bind(t, secID, "security_admin", uuid.Nil)
	g.bind(t, secID, "auditor", uuid.Nil)
	const value = "notify-secret-value-9f1c"

	channel := func(c *http.Client, body map[string]any) response {
		return g.call(t, c, "POST", g.o+"/notification-channels", body)
	}
	if r := channel(g.dev, map[string]any{"kind": "email", "name": "mail"}); r.Status != http.StatusForbidden {
		t.Fatalf("developer created a channel: %d", r.Status)
	}
	r := channel(sec, map[string]any{"kind": "email", "name": "mail"})
	if r.Status != http.StatusCreated {
		t.Fatalf("email channel: %d %s", r.Status, r.Body)
	}
	var mail httpapi.NotificationChannel
	r.decode(t, &mail)

	// The Slack webhook URL lives in the vault, like any other secret.
	hookID, _ := g.secret(t, g.staging, "chat/slack-webhook", g.slack.URL+"/services/T0/B0/token")
	if r := channel(sec, map[string]any{"kind": "slack", "name": "chat", "webhook_secret_id": uuid.New()}); r.Status != http.StatusBadRequest {
		t.Fatalf("unknown webhook secret: %d", r.Status)
	}
	if r := channel(sec, map[string]any{"kind": "slack", "name": "chat"}); r.Status != http.StatusBadRequest {
		t.Fatalf("slack without webhook: %d", r.Status)
	}
	// The creator must be able to read the webhook secret.
	sec2, sec2ID := g.person(t, oidctest.Claims{Subject: "u-sec2", Email: "sec2@example.com", EmailVerified: true}, "member")
	g.bind(t, sec2ID, "security_admin", uuid.Nil)
	if r := channel(sec2, map[string]any{"kind": "slack", "name": "chat", "webhook_secret_id": hookID}); r.Status != http.StatusBadRequest {
		t.Fatalf("channel from an unreadable secret: %d %s", r.Status, r.Body)
	}
	if r := channel(sec, map[string]any{"kind": "slack", "name": "chat", "webhook_secret_id": hookID}); r.Status != http.StatusCreated {
		t.Fatalf("slack channel: %d %s", r.Status, r.Body)
	}
	// A webhook pointing elsewhere is refused at delivery (no request made).
	badID, _ := g.secret(t, g.staging, "chat/bad-webhook", "https://attacker.example/collect")
	if r := channel(sec, map[string]any{"kind": "slack", "name": "elsewhere", "webhook_secret_id": badID}); r.Status != http.StatusCreated {
		t.Fatalf("second slack channel: %d %s", r.Status, r.Body)
	}
	var list struct {
		Channels       []httpapi.NotificationChannel
		EmailAvailable bool `json:"email_available"`
	}
	g.call(t, g.dev, "GET", g.o+"/notification-channels", nil).decode(t, &list)
	if len(list.Channels) != 3 || !list.EmailAvailable {
		t.Fatalf("channels: %+v", list)
	}

	// A production change notifies its approvers.
	g.deliver(t) // flush notifications about the setup itself
	baseline := len(g.slack.received())
	g.slack.failOnce(http.StatusInternalServerError)
	cr := g.mustSubmit(t, g.dev, g.create(g.prod, "notify/db", value))
	g.deliver(t)
	toApprovers := map[string]bool{}
	for _, m := range g.mail.messages() {
		if strings.Contains(m.Data, "Approval requested") {
			toApprovers[m.To] = true
		}
	}
	if !toApprovers["ap1@example.com"] || !toApprovers["ap2@example.com"] || toApprovers["dev@example.com"] || len(toApprovers) != 2 {
		t.Fatalf("approval emails: %v", toApprovers)
	}
	if len(g.slack.received()) != baseline {
		t.Fatal("slack post despite failure")
	}

	// The failed Slack delivery is retried later.
	if _, err := g.db.Owner.Exec(context.Background(), `UPDATE notification_deliveries SET next_attempt_at = now() WHERE status = 'pending'`); err != nil {
		t.Fatal(err)
	}
	g.deliver(t)
	posts := g.slack.received()[baseline:]
	if len(posts) != 1 || !strings.Contains(posts[0], "Approval requested") || !strings.HasPrefix(posts[0], "/services/T0/B0/token ") ||
		!strings.Contains(posts[0], "http://secretmesh.test/orgs/") {
		t.Fatalf("slack posts: %v", posts)
	}

	// The requester hears how it ended.
	if r := g.decide(t, g.ap1, cr.Id, "approve", cr.BindingHash); r.Status != http.StatusOK {
		t.Fatalf("approve: %d", r.Status)
	}
	if err := g.run(t, cr.Id); err != nil {
		t.Fatal(err)
	}
	g.deliver(t)
	applied := false
	for _, m := range g.mail.messages() {
		if m.To == "dev@example.com" && strings.Contains(m.Data, "was applied") {
			applied = true
		}
	}
	if !applied {
		t.Fatal("requester not told the change was applied")
	}

	// Test notifications go only to the caller, through one channel.
	before := len(g.mail.messages())
	if r := g.call(t, sec, "POST", g.o+"/notification-channels/"+mail.Id.String()+"/test", nil); r.Status != http.StatusAccepted {
		t.Fatalf("test channel: %d", r.Status)
	}
	g.deliver(t)
	msgs := g.mail.messages()[before:]
	if len(msgs) != 1 || msgs[0].To != "sec@example.com" {
		t.Fatalf("test messages: %+v", msgs)
	}

	t.Run("approvers are notified only for their environments", func(t *testing.T) {
		before := len(g.mail.messages())
		body := g.create(g.staging, "notify/restricted", "restricted-value-5")
		body["classification"] = "restricted" // restricted needs approval everywhere
		if cr := g.mustSubmit(t, g.dev, body); cr.Status != httpapi.ChangeRequestStatusPending {
			t.Fatalf("restricted staging change: %s", cr.Status)
		}
		g.deliver(t)
		to := map[string]bool{}
		for _, m := range g.mail.messages()[before:] {
			if strings.Contains(m.Data, "Approval requested") {
				to[m.To] = true
			}
		}
		if !to["ap1@example.com"] || to["ap2@example.com"] {
			t.Fatalf("approval emails for staging: %v", to)
		}
	})

	t.Run("deliveries are visible to the security team", func(t *testing.T) {
		if r := g.call(t, g.dev, "GET", g.o+"/notifications", nil); r.Status != http.StatusForbidden {
			t.Fatalf("developer read deliveries: %d", r.Status)
		}
		var ds struct {
			Deliveries []httpapi.NotificationDelivery
		}
		g.call(t, sec, "GET", g.o+"/notifications", nil).decode(t, &ds)
		var refused *httpapi.NotificationDelivery
		for i, d := range ds.Deliveries {
			if d.Channel == "elsewhere" && d.Status == httpapi.NotificationDeliveryStatusFailed {
				refused = &ds.Deliveries[i]
			}
		}
		if refused == nil || refused.LastError == nil || !strings.Contains(*refused.LastError, "not an allowed Slack webhook") ||
			strings.Contains(*refused.LastError, "attacker.example") {
			t.Fatalf("refused webhook delivery: %+v", refused)
		}
	})

	t.Run("no secret values leave SecretMesh in notifications", func(t *testing.T) {
		for _, m := range g.mail.messages() {
			if strings.Contains(m.Data, value) || strings.Contains(m.Data, "/services/T0/B0/token") {
				t.Fatalf("email contains a secret: %s", m.Data)
			}
		}
		for _, p := range g.slack.received() {
			if strings.Contains(p, value) {
				t.Fatal("slack post contains a secret value")
			}
		}
		var dump string
		if err := g.db.Owner.QueryRow(context.Background(), `SELECT coalesce(string_agg(row_to_json(n)::text, ''), '') FROM notifications n`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(dump, value) || strings.Contains(dump, g.slack.URL) {
			t.Fatal("notification outbox contains a secret")
		}
		var deliveries string
		if err := g.db.Owner.QueryRow(context.Background(), `SELECT coalesce(string_agg(row_to_json(d)::text, ''), '')
			FROM notification_deliveries d`).Scan(&deliveries); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(deliveries, g.slack.URL) || strings.Contains(deliveries, "attacker.example") {
			t.Fatal("delivery log contains a webhook URL")
		}
	})

	t.Run("break-glass alerts security and admins", func(t *testing.T) {
		g.bind(t, g.devID, "break_glass", g.prod)
		mfa := g.browser(t)
		c := devClaims
		c.AMR = []string{"mfa"}
		g.login(t, mfa, c)
		body := g.create(g.prod, "notify/emergency", "emergency-value-3")
		body["break_glass"], body["reason"] = true, "INC-9: credential leaked in a public repository"
		g.mustSubmit(t, mfa, body)
		got := g.notifications(t, "change_request.break_glass")
		_, adminMe := getMe(t, g.admin, g.api.URL)
		if len(got) != 1 || !slices.Contains(got[0], secID) || !slices.Contains(got[0], adminMe.User.Id) {
			t.Fatalf("break-glass recipients: %v", got)
		}
	})
}
