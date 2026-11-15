package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretmesh/secretmesh/internal/platform/postgres"
)

var errNotFound = errors.New("not found")

// User is an authenticated human identity.
type User struct {
	ID            uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

type loginState struct {
	Nonce        string
	CodeVerifier string
	StepUp       bool
	ReturnTo     string
	CreatedAt    time.Time
}

type session struct {
	User     User
	AuthTime time.Time // zero if unknown
	MFA      bool
}

// Store persists users, sessions, API tokens and pending OIDC login state.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) createLoginState(ctx context.Context, stateHash []byte, st loginState, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO oidc_login_states (state_hash, nonce, code_verifier, step_up, return_to, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		stateHash, st.Nonce, st.CodeVerifier, st.StepUp, st.ReturnTo, expires)
	return err
}

// consumeLoginState deletes and returns an unexpired login state, so each
// state can be used exactly once.
func (s *Store) consumeLoginState(ctx context.Context, stateHash []byte) (loginState, error) {
	var st loginState
	err := s.pool.QueryRow(ctx, `
		DELETE FROM oidc_login_states
		WHERE state_hash = $1 AND expires_at > now()
		RETURNING nonce, code_verifier, step_up, return_to, created_at`,
		stateHash).Scan(&st.Nonce, &st.CodeVerifier, &st.StepUp, &st.ReturnTo, &st.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, errNotFound
	}
	return st, err
}

var errUserDisabled = errors.New("user disabled")

// loginUser creates or refreshes the user identified by (issuer, subject).
// It runs before any tenant context exists, so it goes through a SECURITY
// DEFINER function (ADR-0008).
func (s *Store) loginUser(ctx context.Context, u User) (User, error) {
	var status string
	err := s.pool.QueryRow(ctx, `SELECT user_id, user_status FROM secretmesh_login_user($1, $2, $3, $4, $5)`,
		u.Issuer, u.Subject, u.Email, u.EmailVerified, u.DisplayName).Scan(&u.ID, &status)
	if err != nil {
		return User{}, fmt.Errorf("login user: %w", err)
	}
	if status != "active" {
		return User{}, errUserDisabled
	}
	return u, nil
}

func (s *Store) createSession(ctx context.Context, idHash []byte, userID uuid.UUID, expires, authTime time.Time, mfa bool) error {
	var at *time.Time
	if !authTime.IsZero() {
		at = &authTime
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (id_hash, user_id, expires_at, auth_time, mfa) VALUES ($1, $2, $3, $4, $5)`,
		idHash, userID, expires, at, mfa)
	return err
}

// lookupSession returns the session and its active user. The session row
// identifies the user; the user row is then read under that user's scope.
func (s *Store) lookupSession(ctx context.Context, idHash []byte) (session, error) {
	var sess session
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var authTime *time.Time
		err := tx.QueryRow(ctx, `
			SELECT user_id, auth_time, mfa FROM sessions
			WHERE id_hash = $1 AND expires_at > now()`,
			idHash).Scan(&sess.User.ID, &authTime, &sess.MFA)
		if err != nil {
			return err
		}
		if authTime != nil {
			sess.AuthTime = *authTime
		}
		if err := postgres.SetScope(ctx, tx, postgres.Scope{UserID: sess.User.ID}); err != nil {
			return err
		}
		u := &sess.User
		return tx.QueryRow(ctx, `
			SELECT issuer, subject, email, email_verified, display_name
			FROM users WHERE id = $1 AND status = 'active'`,
			u.ID).Scan(&u.Issuer, &u.Subject, &u.Email, &u.EmailVerified, &u.DisplayName)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return session{}, errNotFound
	}
	return sess, err
}

func (s *Store) deleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
	return err
}

// PurgeExpired removes expired sessions and login states.
func (s *Store) PurgeExpired(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM oidc_login_states WHERE expires_at <= now()`)
	return err
}
