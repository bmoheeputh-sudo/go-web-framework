package authconfig

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalid                     = errors.New("auth_config_invalid")
	ErrDenied                      = errors.New("auth_config_denied")
	ErrConflict                    = errors.New("auth_config_conflict")
	ErrNotFound                    = errors.New("auth_config_not_found")
	ErrUnavailable                 = errors.New("auth_config_unavailable")
	ErrTimeout                     = errors.New("auth_config_timeout")
	ErrCanceled                    = errors.New("auth_config_canceled")
	ErrAudit                       = errors.New("auth_config_audit_failed")
	ErrRecoveryProviderUnavailable = errors.New("auth_config_recovery_provider_unavailable")
)

type Scope struct {
	DeploymentID string `json:"deployment_id"`
	Environment  string `json:"environment"`
}

var deploymentID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func (s Scope) valid() bool {
	return deploymentID.MatchString(s.DeploymentID) && (s.Environment == "development" || s.Environment == "test" || s.Environment == "production")
}

// Scope is deployment-owned configuration, never derived from request data.
func ScopeFromEnv(getenv func(string) string) (Scope, error) {
	s := Scope{DeploymentID: getenv("AUTH_CONFIG_DEPLOYMENT"), Environment: getenv("APP_ENV")}
	switch s.Environment {
	case "TEST":
		s.Environment = "test"
	case "PRD", "prd":
		s.Environment = "production"
	}
	if !s.valid() {
		return Scope{}, ErrInvalid
	}
	return s, nil
}

type Settings struct {
	Provider             auth.Provider `json:"provider"`
	IssuerURL            string        `json:"issuer_url"`
	ClientID             string        `json:"client_id"`
	RedirectURI          string        `json:"redirect_uri"`
	IAPAudience          string        `json:"iap_audience"`
	AllowHTTPDevelopment bool          `json:"allow_http_development"`
}
type Status string

const (
	Draft      Status = "draft"
	Validated  Status = "validated"
	Approved   Status = "approved"
	Active     Status = "active"
	Superseded Status = "superseded"
)

type Validation struct {
	Check   string `json:"check,omitempty"`
	Version int    `json:"version,omitempty"`
}
type Metadata struct {
	ID string `json:"id"`
	Scope
	Version int64 `json:"configuration_version"`
	Settings
	Status           Status     `json:"status"`
	Generation       int64      `json:"generation"`
	CreatedBy        string     `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedBy        string     `json:"updated_by"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Validation       Validation `json:"validation"`
	ValidatedAt      *time.Time `json:"validated_at,omitempty"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	SupersededAt     *time.Time `json:"superseded_at,omitempty"`
	HasSecret        bool       `json:"has_secret"`
	EncryptionFormat int        `json:"encryption_format,omitempty"`
	EncryptionKeyID  string     `json:"encryption_key_id,omitempty"`
}

// Repository is a deployment-bound internal administrator capability. Metadata never has a secret
// field. No method changes immutable revision settings or activates a provider.
type Repository struct {
	access *access.Store
	scope  Scope
	cipher *Cipher
}

func NewRepository(store *access.Store, scope Scope, cipher *Cipher) (*Repository, error) {
	if store == nil || !scope.valid() {
		return nil, ErrInvalid
	}
	if cipher == nil || cipher.aead == nil {
		return nil, ErrKey
	}
	return &Repository{store, scope, cipher}, nil
}
func (*Repository) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("[AUTH CONFIG REPOSITORY]"))
}

func validID(id string) bool { var v pgtype.UUID; return len(id) == 36 && v.Scan(id) == nil && v.Valid }
func validate(scope Scope, s Settings, secret Secret) error {
	for _, field := range []string{s.IssuerURL, s.ClientID, s.RedirectURI, s.IAPAudience} {
		if strings.TrimSpace(field) != field || strings.ContainsFunc(field, unicode.IsControl) {
			return ErrInvalid
		}
	}
	if len(s.IssuerURL) > 2048 || len(s.RedirectURI) > 2048 || len(s.ClientID) > 512 || len(s.IAPAudience) > 512 {
		return ErrInvalid
	}
	if s.Provider == auth.OIDC {
		if s.IAPAudience != "" || len(secret.value) > 4096 || len(bytes.TrimSpace(secret.value)) == 0 {
			return ErrInvalid
		}
		config := auth.OIDCConfig{AppEnv: scope.Environment, Issuer: s.IssuerURL, ClientID: s.ClientID, ClientSecret: "present", RedirectURI: s.RedirectURI, AllowHTTPDevelopment: s.AllowHTTPDevelopment, Sessions: auth.SessionConfig{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: 8 * time.Hour}}
		if config.Validate() != nil {
			return ErrInvalid
		}
		return nil
	}
	if s.IssuerURL != "" || s.ClientID != "" || s.RedirectURI != "" || s.AllowHTTPDevelopment || len(secret.value) != 0 {
		return ErrInvalid
	}
	switch s.Provider {
	case auth.LocalDev:
		if scope.Environment != "development" || s.IAPAudience != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (r *Repository) transaction(ctx context.Context, fn func(context.Context, pgx.Tx, access.User) error) error {
	return adminTransaction(ctx, r.access, fn)
}

func adminTransaction(ctx context.Context, store *access.Store, fn func(context.Context, pgx.Tx, access.User) error) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return repositoryError(ctx, store.AdminTransaction(ctx, fn))
}

func repositoryError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return ErrCanceled
	}
	switch {
	case errors.Is(err, access.ErrDenied):
		return ErrDenied
	case errors.Is(err, access.ErrCommitUncertain):
		return ErrCommitUncertain
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	}
	for _, known := range []error{ErrInvalid, ErrDenied, ErrConflict, ErrNotFound, ErrSecret, ErrCrypto, ErrAudit, ErrLastOIDCAdministrator} {
		if errors.Is(err, known) {
			return known
		}
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "23514" || pg.Code == "23503" || pg.Code == "22P02") {
		return ErrInvalid
	}
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return ErrUnavailable
}
func record(ctx context.Context, tx pgx.Tx, actor access.User, action string, m Metadata) error {
	details := struct {
		Version    int64  `json:"configuration_version"`
		Generation int64  `json:"generation"`
		Status     Status `json:"status"`
	}{m.Version, m.Generation, m.Status}
	if access.RecordAudit(ctx, tx, actor.ID, action, m.ID, details) != nil {
		return ErrAudit
	}
	return nil
}

const metadataSelect = `SELECT r.id::text,r.deployment_id,r.environment,r.configuration_version,r.provider,r.issuer_url,r.client_id,r.redirect_uri,r.iap_audience,r.allow_http_development,
 l.status,l.generation,r.created_by::text,r.created_at,COALESCE(l.updated_by::text,''),l.updated_at,l.validation,l.validated_at,l.approved_at,l.activated_at,l.superseded_at,
 r.secret_ciphertext IS NOT NULL,COALESCE(r.encryption_format,0),COALESCE(r.encryption_key_id,'')
 FROM framework.auth_config_revisions r JOIN framework.auth_config_lifecycle l ON l.revision_id=r.id
 WHERE r.deployment_id=$1 AND r.environment=$2 `

func scanMetadata(row pgx.Row) (Metadata, error) {
	var m Metadata
	var validation []byte
	err := row.Scan(&m.ID, &m.DeploymentID, &m.Environment, &m.Version, &m.Provider, &m.IssuerURL, &m.ClientID, &m.RedirectURI, &m.IAPAudience, &m.AllowHTTPDevelopment,
		&m.Status, &m.Generation, &m.CreatedBy, &m.CreatedAt, &m.UpdatedBy, &m.UpdatedAt, &validation, &m.ValidatedAt, &m.ApprovedAt, &m.ActivatedAt, &m.SupersededAt, &m.HasSecret, &m.EncryptionFormat, &m.EncryptionKeyID)
	if err != nil {
		return Metadata{}, err
	}
	if json.Unmarshal(validation, &m.Validation) != nil {
		return Metadata{}, ErrUnavailable
	}
	return m, nil
}
func (r *Repository) get(ctx context.Context, tx pgx.Tx, id string) (Metadata, error) {
	return scanMetadata(tx.QueryRow(ctx, metadataSelect+`AND r.id=$3`, r.scope.DeploymentID, r.scope.Environment, id))
}
func (r *Repository) LatestVersion(ctx context.Context) (int64, error) {
	var version int64
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		return tx.QueryRow(ctx, `SELECT COALESCE(max(configuration_version),0) FROM framework.auth_config_revisions WHERE deployment_id=$1 AND environment=$2`, r.scope.DeploymentID, r.scope.Environment).Scan(&version)
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}
func (r *Repository) CreateDraft(ctx context.Context, expectedLatestVersion int64, settings Settings, secret Secret) (Metadata, error) {
	return r.createDraft(ctx, expectedLatestVersion, settings, secret, "", "")
}
func (r *Repository) createDraft(ctx context.Context, expectedLatestVersion int64, settings Settings, secret Secret, recovery, recoveryReason string) (Metadata, error) {
	if expectedLatestVersion < 0 || expectedLatestVersion == math.MaxInt64 || validate(r.scope, settings, secret) != nil {
		return Metadata{}, ErrInvalid
	}
	var result Metadata
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(configuration_version),0) FROM framework.auth_config_revisions WHERE deployment_id=$1 AND environment=$2`, r.scope.DeploymentID, r.scope.Environment).Scan(&version); err != nil {
			return err
		}
		if version != expectedLatestVersion {
			return ErrConflict
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return ErrUnavailable
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		raw := hex.EncodeToString(id[:])
		uuid := raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:]
		m := Metadata{ID: uuid, Scope: r.scope, Version: version + 1, Settings: settings, CreatedBy: actor.ID}
		var encrypted encryptedSecret
		var format, keyID any
		if settings.Provider == auth.OIDC {
			var err error
			encrypted, err = r.cipher.seal(m, secret)
			if err != nil {
				return err
			}
			format, keyID = encrypted.format, encrypted.keyID
		}
		_, err := tx.Exec(ctx, `INSERT INTO framework.auth_config_revisions(id,deployment_id,environment,configuration_version,provider,issuer_url,client_id,redirect_uri,iap_audience,allow_http_development,secret_ciphertext,secret_nonce,encryption_format,encryption_key_id,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, m.ID, m.DeploymentID, m.Environment, m.Version, m.Provider, m.IssuerURL, m.ClientID, m.RedirectURI, m.IAPAudience, m.AllowHTTPDevelopment, encrypted.ciphertext, encrypted.nonce, format, keyID, actor.ID)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO framework.auth_config_lifecycle(revision_id,deployment_id,environment,updated_by) VALUES($1,$2,$3,$4)`, m.ID, m.DeploymentID, m.Environment, actor.ID); err != nil {
			return err
		}
		result, err = r.get(ctx, tx, m.ID)
		if err != nil {
			return err
		}
		if recovery != "" {
			historical, err := r.get(ctx, tx, recovery)
			if err != nil {
				return err
			}
			if historical.Status != Superseded || historical.Settings != settings {
				return ErrConflict
			}
			if access.RecordAudit(ctx, tx, actor.ID, "auth_config.recovery_draft", result.ID, struct {
				Recovery string `json:"recovery_revision_id"`
				Reason   string `json:"reason,omitempty"`
			}{recovery, recoveryReason}) != nil {
				return ErrAudit
			}
		}
		return record(ctx, tx, actor, "auth_config.draft_created", result)
	})
	if err != nil {
		return Metadata{}, err
	}
	return result, nil
}
func (r *Repository) Read(ctx context.Context, id string) (Metadata, error) {
	if !validID(id) {
		return Metadata{}, ErrInvalid
	}
	var result Metadata
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		result, err = r.get(ctx, tx, id)
		return err
	})
	if err != nil {
		return Metadata{}, err
	}
	return result, nil
}
func (r *Repository) List(ctx context.Context, beforeVersion int64, limit int) ([]Metadata, error) {
	if beforeVersion < 0 || limit < 1 || limit > 100 {
		return nil, ErrInvalid
	}
	result := []Metadata{}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		rows, err := tx.Query(ctx, metadataSelect+`AND ($3::bigint=0 OR r.configuration_version<$3) ORDER BY r.configuration_version DESC LIMIT $4`, r.scope.DeploymentID, r.scope.Environment, beforeVersion, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanMetadata(rows)
			if err != nil {
				return err
			}
			result = append(result, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
func (r *Repository) CurrentActive(ctx context.Context) (Metadata, error) {
	var result Metadata
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		result, err = scanMetadata(tx.QueryRow(ctx, metadataSelect+`AND l.status='active'`, r.scope.DeploymentID, r.scope.Environment))
		return err
	})
	if err != nil {
		return Metadata{}, err
	}
	return result, nil
}

// Transition only performs offline static validation or records an explicit
// approval. No discovery, handshake, activation, supersession or provider switch.
// Validation metadata is generated here, never taken from a caller-supplied map.
func (r *Repository) Transition(ctx context.Context, id string, expectedGeneration int64, to Status) (Metadata, error) {
	if !validID(id) || expectedGeneration < 1 || (to != Validated && to != Approved) {
		return Metadata{}, ErrInvalid
	}
	var result Metadata
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		m, err := r.get(ctx, tx, id)
		if err != nil {
			return err
		}
		if m.Generation != expectedGeneration {
			return ErrConflict
		}
		// Legacy IAP revisions remain readable, never actionable.
		if m.Provider != auth.OIDC && m.Provider != auth.LocalDev {
			return ErrInvalid
		}
		if (to == Validated && m.Status != Draft) || (to == Approved && m.Status != Validated) {
			return ErrInvalid
		}
		if to == Validated {
			var secret Secret
			if m.Provider == auth.OIDC {
				secret, err = r.readSecret(ctx, tx, m)
				if err != nil {
					return err
				}
				defer clear(secret.value)
			}
			if validate(r.scope, m.Settings, secret) != nil {
				return ErrInvalid
			}
		}
		validation := Validation{Check: "static", Version: 1}
		data, _ := json.Marshal(validation)
		tag, err := tx.Exec(ctx, `UPDATE framework.auth_config_lifecycle SET status=$1,generation=generation+1,updated_by=$2,validation=$3 WHERE revision_id=$4 AND deployment_id=$5 AND environment=$6 AND generation=$7`, to, actor.ID, data, id, r.scope.DeploymentID, r.scope.Environment, expectedGeneration)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		result, err = r.get(ctx, tx, id)
		if err != nil {
			return err
		}
		return record(ctx, tx, actor, "auth_config."+string(to), result)
	})
	if err != nil {
		return Metadata{}, err
	}
	return result, nil
}
func (r *Repository) readSecret(ctx context.Context, tx pgx.Tx, m Metadata) (Secret, error) {
	if !m.HasSecret || m.Provider != auth.OIDC {
		return Secret{}, ErrSecret
	}
	var encrypted encryptedSecret
	err := tx.QueryRow(ctx, `SELECT encryption_format,encryption_key_id,secret_nonce,secret_ciphertext FROM framework.auth_config_revisions WHERE id=$1 AND deployment_id=$2 AND environment=$3`, m.ID, r.scope.DeploymentID, r.scope.Environment).Scan(&encrypted.format, &encrypted.keyID, &encrypted.nonce, &encrypted.ciphertext)
	if err != nil {
		return Secret{}, err
	}
	return r.cipher.open(m, encrypted)
}

// ReadSecretPrivileged requires the same verified, active administrator context as
// writes and audits access before releasing a redacted Secret wrapper. It is not
// an HTTP response type or a startup/runtime provider loader.
func (r *Repository) ReadSecretPrivileged(ctx context.Context, id string) (Secret, error) {
	if !validID(id) {
		return Secret{}, ErrInvalid
	}
	var result Secret
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		m, err := r.get(ctx, tx, id)
		if err != nil {
			return err
		}
		result, err = r.readSecret(ctx, tx, m)
		if err != nil {
			return err
		}
		return record(ctx, tx, actor, "auth_config.secret_access", m)
	})
	if err != nil {
		clear(result.value)
		return Secret{}, err
	}
	return result, nil
}
