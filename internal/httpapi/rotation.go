package httpapi

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/secretmesh/secretmesh/internal/audit"
	"github.com/secretmesh/secretmesh/internal/auth"
	"github.com/secretmesh/secretmesh/internal/connectors"
	"github.com/secretmesh/secretmesh/internal/inventory"
	"github.com/secretmesh/secretmesh/internal/notify"
	"github.com/secretmesh/secretmesh/internal/platform/httpx"
	"github.com/secretmesh/secretmesh/internal/platform/postgres"
	"github.com/secretmesh/secretmesh/internal/rotation"
)

func (a *api) rotationError(w http.ResponseWriter, r *http.Request, err error) {
	var invalid rotation.InvalidError
	switch {
	case errors.As(err, &invalid):
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", invalid.Msg)
	case errors.Is(err, rotation.ErrNotFound):
		notFound(w, r)
	case errors.Is(err, rotation.ErrNoPolicy):
		httpx.WriteError(w, r, http.StatusNotFound, "no_rotation_policy", err.Error())
	case errors.Is(err, rotation.ErrForbidden):
		httpx.WriteError(w, r, http.StatusForbidden, "forbidden", "missing permission "+string(auth.SecretManage))
	case errors.Is(err, rotation.ErrMFARequired):
		httpx.WriteError(w, r, http.StatusForbidden, "mfa_required", err.Error())
	case errors.Is(err, rotation.ErrInProgress):
		httpx.WriteError(w, r, http.StatusConflict, "rotation_in_progress", err.Error())
	case errors.Is(err, rotation.ErrChangeInProgress):
		httpx.WriteError(w, r, http.StatusConflict, "change_in_progress", err.Error())
	case errors.Is(err, rotation.ErrNotConfigured):
		httpx.WriteError(w, r, http.StatusBadRequest, "rotation_not_configured",
			"the secret has no rotation function in the provider; configure one there or use the manual strategy")
	case errors.Is(err, connectors.ErrAccessDenied), errors.Is(err, connectors.ErrNotFound),
		errors.Is(err, connectors.ErrTransient), errors.Is(err, connectors.ErrProviderUnavailable):
		a.providerError(w, r, "rotation", err)
	default:
		a.internal(w, r, "rotation", err)
	}
}

func rotationPolicyJSON(p rotation.Policy) RotationPolicy {
	return RotationPolicy{SecretId: p.SecretID, Strategy: RotationStrategy(p.Strategy), IntervalDays: p.IntervalDays,
		ReminderDays: nonNil(p.ReminderDays), EscalationDays: nonNil(p.EscalationDays), Enabled: p.Enabled,
		NextRotationAt: p.NextRotationAt, UpdatedBy: p.UpdatedBy, UpdatedAt: p.UpdatedAt}
}

func nonNil(d []int) []int {
	if d == nil {
		return []int{}
	}
	return d
}

func rotationJSON(e rotation.Execution) RotationExecution {
	return RotationExecution{Id: e.ID, SecretId: e.SecretID, Trigger: RotationExecutionTrigger(e.Trigger),
		RequestedBy: e.RequestedBy, Status: RotationExecutionStatus(e.Status), DueAt: e.DueAt,
		ProviderVersionId: opt(e.ProviderVersionID), CloudRequestId: opt(e.CloudRequestID), ErrorCode: opt(e.ErrorCode),
		RotateStartedAt: e.RotateStartedAt, FinishedAt: e.FinishedAt, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt}
}

func (a *api) UpdateSecret(w http.ResponseWriter, r *http.Request, orgID OrgId, id openapi_types.UUID) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	var body UpdateSecret
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	owner := uuid.Nil
	if body.OwnerUserId != nil {
		owner = *body.OwnerUserId
	}
	if err := a.d.Rotation.SetOwner(r.Context(), access, id, owner); err != nil {
		a.rotationError(w, r, err)
		return
	}
	a.GetSecret(w, r, orgID, id)
}

func (a *api) GetRotationPolicy(w http.ResponseWriter, r *http.Request, orgID OrgId, id SecretId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	p, err := a.d.Rotation.Policy(r.Context(), access, id)
	if err != nil {
		a.rotationError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rotationPolicyJSON(p))
}

func (a *api) SetRotationPolicy(w http.ResponseWriter, r *http.Request, orgID OrgId, id SecretId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	var body SetRotationPolicy
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if !a.requireStepUp(w, r, access) {
		return
	}
	in := rotation.PolicyInput{Strategy: string(body.Strategy), IntervalDays: body.IntervalDays, Enabled: true}
	if body.Enabled != nil {
		in.Enabled = *body.Enabled
	}
	if body.ReminderDays != nil {
		in.ReminderDays = *body.ReminderDays
	}
	if body.EscalationDays != nil {
		in.EscalationDays = *body.EscalationDays
	}
	p, err := a.d.Rotation.SetPolicy(r.Context(), access, id, in)
	if err != nil {
		a.rotationError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rotationPolicyJSON(p))
}

func (a *api) DeleteRotationPolicy(w http.ResponseWriter, r *http.Request, orgID OrgId, id SecretId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok || !a.requireStepUp(w, r, access) {
		return
	}
	if err := a.d.Rotation.DeletePolicy(r.Context(), access, id); err != nil {
		a.rotationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) RotateSecret(w http.ResponseWriter, r *http.Request, orgID OrgId, id SecretId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok || !a.requireStepUp(w, r, access) {
		return
	}
	ex, err := a.d.Rotation.RotateNow(r.Context(), access, id)
	if err != nil {
		a.rotationError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, rotationJSON(ex))
}

func (a *api) ListRotations(w http.ResponseWriter, r *http.Request, orgID OrgId, id SecretId) {
	access, ok := a.authorize(w, r, orgID, auth.OrgRead)
	if !ok {
		return
	}
	exs, err := a.d.Rotation.Executions(r.Context(), access, id)
	if err != nil {
		a.rotationError(w, r, err)
		return
	}
	out := make([]RotationExecution, 0, len(exs))
	for _, e := range exs {
		out = append(out, rotationJSON(e))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"rotations": out})
}

// ---- Notifications ----

func channelJSON(c notify.Channel) NotificationChannel {
	out := NotificationChannel{Id: c.ID, Kind: NotificationChannelKind(c.Kind), Name: c.Name, Enabled: c.Enabled, CreatedAt: c.CreatedAt}
	if c.WebhookSecretID != uuid.Nil {
		out.WebhookSecretId = &c.WebhookSecretID
	}
	return out
}

func (a *api) ListNotificationChannels(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorize(w, r, orgID, auth.OrgRead); !ok {
		return
	}
	var chs []notify.Channel
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		var err error
		chs, err = notify.Channels(r.Context(), tx, orgID)
		return err
	})
	if err != nil {
		a.internal(w, r, "list channels", err)
		return
	}
	out := make([]NotificationChannel, 0, len(chs))
	for _, c := range chs {
		out = append(out, channelJSON(c))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"channels": out, "email_available": a.d.Deliverer.EmailConfigured()})
}

func (a *api) CreateNotificationChannel(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	access, ok := a.authorizeOn(w, r, orgID, auth.NotificationsManage, uuid.Nil)
	if !ok {
		return
	}
	var body CreateNotificationChannel
	if !httpx.DecodeJSON(w, r, &body) {
		return
	}
	if !a.requireStepUp(w, r, access) {
		return
	}
	c := notify.Channel{Kind: string(body.Kind), Name: body.Name}
	switch {
	case len(body.Name) < 1 || len(body.Name) > 100:
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "name must be 1-100 characters")
		return
	case body.Kind == CreateNotificationChannelKindEmail && !a.d.Deliverer.EmailConfigured():
		httpx.WriteError(w, r, http.StatusBadRequest, "email_unavailable", "this deployment has no SMTP server configured")
		return
	case body.Kind == CreateNotificationChannelKindEmail && body.WebhookSecretId != nil:
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "email channels take no webhook")
		return
	case body.Kind == CreateNotificationChannelKindSlack && body.WebhookSecretId == nil:
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "slack channels need webhook_secret_id")
		return
	case body.Kind != CreateNotificationChannelKindEmail && body.Kind != CreateNotificationChannelKindSlack:
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "kind must be email or slack")
		return
	}
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		if body.WebhookSecretId != nil {
			// The webhook secret must be one the caller can read, so a channel
			// cannot be used to make SecretMesh read a secret on someone's behalf.
			s, err := inventory.SecretTx(r.Context(), tx, orgID, *body.WebhookSecretId)
			if errors.Is(err, inventory.ErrNotFound) || (err == nil && (s.Status != "active" || !access.CanOn(auth.SecretRead, s.EnvironmentID))) {
				return errWebhookSecret
			}
			if err != nil {
				return err
			}
			c.WebhookSecretID = s.ID
		}
		var err error
		if c, err = notify.CreateChannel(r.Context(), tx, orgID, c, access.Principal.UserID); err != nil {
			return err
		}
		_, err = audit.Append(r.Context(), tx, orgID, audit.Event{
			Action: "notification_channel.created", ResourceType: "notification_channel", ResourceID: c.ID.String(),
			Decision: audit.Allow, Details: map[string]string{"kind": c.Kind, "name": c.Name},
		})
		return err
	})
	switch {
	case errors.Is(err, errWebhookSecret):
		httpx.WriteError(w, r, http.StatusBadRequest, "invalid_request", "unknown webhook secret")
	case errors.Is(err, notify.ErrChannelExists):
		httpx.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case err != nil:
		a.internal(w, r, "create channel", err)
	default:
		httpx.WriteJSON(w, http.StatusCreated, channelJSON(c))
	}
}

var errWebhookSecret = errors.New("webhook secret")

func (a *api) DeleteNotificationChannel(w http.ResponseWriter, r *http.Request, orgID OrgId, id ChannelId) {
	if _, ok := a.authorizeOn(w, r, orgID, auth.NotificationsManage, uuid.Nil); !ok {
		return
	}
	found := false
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		var err error
		if found, err = notify.DeleteChannel(r.Context(), tx, orgID, id); err != nil || !found {
			return err
		}
		_, err = audit.Append(r.Context(), tx, orgID, audit.Event{
			Action: "notification_channel.deleted", ResourceType: "notification_channel", ResourceID: id.String(), Decision: audit.Allow,
		})
		return err
	})
	switch {
	case err != nil:
		a.internal(w, r, "delete channel", err)
	case !found:
		notFound(w, r)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (a *api) TestNotificationChannel(w http.ResponseWriter, r *http.Request, orgID OrgId, id ChannelId) {
	access, ok := a.authorizeOn(w, r, orgID, auth.NotificationsManage, uuid.Nil)
	if !ok {
		return
	}
	if access.Principal.Kind != auth.KindUser {
		httpx.WriteError(w, r, http.StatusForbidden, "session_required", "this operation requires a user session")
		return
	}
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		if _, err := notify.ChannelTx(r.Context(), tx, orgID, id); err != nil {
			return err
		}
		_, err := notify.Enqueue(r.Context(), tx, orgID, notify.Event{
			Kind: notify.ChannelTest, Subject: "SecretMesh test notification",
			Body:       "This is a test notification. If you can read it, the channel works.",
			Recipients: []uuid.UUID{access.Principal.UserID}, ChannelID: id,
		})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		notFound(w, r)
		return
	}
	if err != nil {
		a.internal(w, r, "test channel", err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (a *api) ListNotificationDeliveries(w http.ResponseWriter, r *http.Request, orgID OrgId) {
	if _, ok := a.authorizeOn(w, r, orgID, auth.NotificationsManage, uuid.Nil); !ok {
		return
	}
	var ds []notify.Delivery
	err := postgres.Tx(r.Context(), a.d.Pool, func(tx pgx.Tx) error {
		var err error
		ds, err = notify.Recent(r.Context(), tx, orgID, 100)
		return err
	})
	if err != nil {
		a.internal(w, r, "list deliveries", err)
		return
	}
	out := make([]NotificationDelivery, 0, len(ds))
	for _, d := range ds {
		out = append(out, NotificationDelivery{NotificationId: d.NotificationID, Event: d.Event, Subject: d.Subject,
			Channel: d.ChannelName, Status: NotificationDeliveryStatus(d.Status), Attempts: d.Attempts,
			LastError: opt(d.LastError), CreatedAt: d.CreatedAt, SentAt: d.SentAt})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deliveries": out})
}

// opt returns nil for empty strings (omitted in JSON).
func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
