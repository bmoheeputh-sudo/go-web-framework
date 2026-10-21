package authconfig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

const importPreviewTTL = 5 * time.Minute

type ImportExpectation struct {
	PolicyGeneration     int64  `json:"expected_policy_generation"`
	ActivationGeneration int64  `json:"expected_activation_generation"`
	RevisionID           string `json:"revision_id"`
	RevisionGeneration   int64  `json:"expected_revision_generation"`
}

func (e ImportExpectation) invitation() InvitationExpectation {
	return InvitationExpectation{PolicyExpectation{e.PolicyGeneration, e.ActivationGeneration}, e.RevisionID, e.RevisionGeneration}
}
func importExpectation(b invitationBinding) ImportExpectation {
	return ImportExpectation{b.policy.Generation, b.activationGeneration, b.revision, b.revisionGeneration}
}

type CSVPreviewRequest struct {
	CSV            string `json:"csv"`
	SelectedRows   []int  `json:"selected_rows"`
	ExpirationDays int    `json:"expiration_days"`
	ImportExpectation
}
type CSVPreview struct {
	ImportExpectation
	Rows           []CSVRow  `json:"rows"`
	SelectedRows   []int     `json:"selected_rows"`
	Total          int       `json:"total_rows"`
	Ready          int       `json:"ready_rows"`
	Skipped        int       `json:"skipped_rows"`
	Invalid        int       `json:"invalid_rows"`
	WillCreate     int       `json:"will_create"`
	ExpirationDays int       `json:"expiration_days"`
	ContentDigest  string    `json:"content_digest"`
	PreviewDigest  string    `json:"preview_digest"`
	ExpiresAt      time.Time `json:"preview_expires_at"`
	MaxRows        int       `json:"max_rows"`
	MaxBytes       int       `json:"max_bytes"`
}
type CSVImportRequest struct {
	CSVPreviewRequest
	ImportID         string    `json:"import_id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	PreviewDigest    string    `json:"preview_digest"`
	PreviewExpiresAt time.Time `json:"preview_expires_at"`
	Reason           string    `json:"reason"`
	Confirm          bool      `json:"confirm"`
}
type ImportReceipt struct {
	ID string `json:"id"`
	Scope
	ActorUserID   string `json:"actor_user_id"`
	ContentDigest string `json:"content_digest"`
	ImportExpectation
	ExpirationDays int       `json:"expiration_days"`
	Total          int       `json:"total_rows"`
	SelectedRows   []int     `json:"selected_rows"`
	Created        int       `json:"created_count"`
	Skipped        int       `json:"skipped_count"`
	Rejected       int       `json:"rejected_count"`
	InvitationIDs  []string  `json:"created_invitation_ids"`
	CreatedAt      time.Time `json:"created_at"`
	CompletedAt    time.Time `json:"completed_at"`
	Outcome        string    `json:"outcome"`
	Reason         string    `json:"reason"`
}

func requireImportOIDC(ctx context.Context) error {
	identity, ok := auth.IdentityFromContext(ctx)
	if !ok || identity.Provider != auth.OIDC || identity.Validate() != nil {
		return ErrDenied
	}
	return nil
}
func importDays(days int) (int, error) {
	if days == 0 {
		return 7, nil
	}
	if days < 1 || days > 30 {
		return 0, ErrInvalid
	}
	return days, nil
}
func shaText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (r *AccessPolicyRepository) classifyCSV(ctx context.Context, tx pgx.Tx, b invitationBinding, rows []CSVRow, now time.Time) error {
	keys := []string{}
	for n := range rows {
		if rows[n].Status != "ready" {
			continue
		}
		if !policyEmailAllowed(b.policy.AllowedEmailDomains, rows[n].key, true) {
			rows[n].Status = "blocked_domain"
			continue
		}
		keys = append(keys, strings.ToLower(rows[n].key))
	}
	if len(keys) == 0 {
		return nil
	}
	// Scan matches as a set, rather than issuing a lookup per employee. Mailbox
	// matches are informational only; no user or approval is selected for mutation.
	data, err := tx.Query(ctx, `WITH invitations AS (
 SELECT lower(email_key COLLATE "C") AS key,bool_or(status='claimed') AS claimed,
 bool_or(status='pending' AND expires_at>$9 AND revision_id=$4 AND revision_generation=$5 AND activation_generation=$6 AND issuer=$7 AND client_id=$8) AS pending,
 bool_or(status='pending' AND expires_at>$9 AND NOT (revision_id=$4 AND revision_generation=$5 AND activation_generation=$6 AND issuer=$7 AND client_id=$8)) AS stale
 FROM framework.oidc_invitations WHERE deployment_id=$1 AND environment=$2 AND lower(email_key COLLATE "C")=ANY($3::text[]) GROUP BY 1
 ), users AS (SELECT DISTINCT lower(framework.invitation_email_key(email) COLLATE "C") AS key FROM framework.users
 WHERE lower(framework.invitation_email_key(email) COLLATE "C")=ANY($3::text[]))
 SELECT k.key,COALESCE(i.claimed,false),COALESCE(i.pending,false),COALESCE(i.stale,false),u.key IS NOT NULL
 FROM unnest($3::text[]) k(key) LEFT JOIN invitations i USING(key) LEFT JOIN users u USING(key)`, r.scope.DeploymentID, r.scope.Environment, keys, b.revision, b.revisionGeneration, b.activationGeneration, b.issuer, b.client, now)
	if err != nil {
		return err
	}
	defer data.Close()
	found := map[string]string{}
	for data.Next() {
		var key string
		var claimed, pending, stale, user bool
		if err := data.Scan(&key, &claimed, &pending, &stale, &user); err != nil {
			return err
		}
		switch {
		case claimed:
			found[key] = "already_claimed"
		case user:
			found[key] = "existing_user_review"
		case pending:
			found[key] = "existing_pending"
		case stale:
			found[key] = "stale_configuration_or_policy"
		}
	}
	if err = data.Err(); err != nil {
		return err
	}
	for n := range rows {
		if rows[n].Status == "ready" {
			if status := found[strings.ToLower(rows[n].key)]; status != "" {
				rows[n].Status = status
			}
		}
	}
	return nil
}
func importSummary(rows []CSVRow, selected []int) (ready, skipped, invalid int) {
	for _, row := range rows {
		switch row.Status {
		case "ready":
			ready++
		case "invalid_email", "invalid_display_name", "blocked_domain", "stale_configuration_or_policy":
			invalid++
		default:
			skipped++
		}
	}
	skipped += ready - len(selected)
	return
}
func csvProof(ctx context.Context, tx pgx.Tx, scope Scope, actor string, request CSVPreviewRequest, rows []CSVRow, selected []int, expires time.Time) (string, error) {
	var key []byte
	if err := tx.QueryRow(ctx, `SELECT signing_key FROM framework.oidc_invitation_import_keys WHERE singleton`).Scan(&key); err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", ErrUnavailable
	}
	statuses := make([]string, len(rows))
	for n, row := range rows {
		statuses[n] = row.Status
	}
	proof := struct {
		Version        int
		Scope          Scope
		Actor, Content string
		Expected       ImportExpectation
		Selected       []int
		Days           int
		Expires        time.Time
		States         []string
	}{1, scope, actor, shaText(request.CSV), request.ImportExpectation, selected, request.ExpirationDays, expires.UTC(), statuses}
	payload, err := json.Marshal(proof)
	if err != nil {
		return "", ErrUnavailable
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func (r *AccessPolicyRepository) PreviewInvitationCSV(ctx context.Context, input CSVPreviewRequest) (CSVPreview, error) {
	var result CSVPreview
	if err := requireImportOIDC(ctx); err != nil {
		return result, err
	}
	rows, err := parseInvitationCSV(input.CSV)
	if err != nil {
		return result, err
	}
	days, err := importDays(input.ExpirationDays)
	if err != nil {
		return result, err
	}
	input.ExpirationDays = days
	expected := input.ImportExpectation.invitation()
	if !expected.valid() {
		return result, ErrInvalid
	}
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		b, err := r.invitationContext(ctx, tx, nil)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		current := importExpectation(b)
		if input.ImportExpectation != current {
			for n := range rows {
				if rows[n].Status == "ready" {
					rows[n].Status = "stale_configuration_or_policy"
				}
			}
		} else if err = r.classifyCSV(ctx, tx, b, rows, now); err != nil {
			return err
		}
		selected, err := selectedCSVRows(rows, input.SelectedRows, false)
		if err != nil {
			return err
		}
		result = CSVPreview{ImportExpectation: current, Rows: rows, SelectedRows: selected, Total: len(rows), WillCreate: len(selected), ExpirationDays: days, ContentDigest: shaText(input.CSV), ExpiresAt: now.Add(importPreviewTTL), MaxRows: CSVMaxRows, MaxBytes: CSVMaxBytes}
		result.Ready, result.Skipped, result.Invalid = importSummary(rows, selected)
		// A stale initial preview displays authoritative current expectations, but
		// cannot be submitted until the administrator explicitly previews again.
		if input.ImportExpectation != current {
			return nil
		}
		result.PreviewDigest, err = csvProof(ctx, tx, r.scope, actor.ID, input, rows, selected, result.ExpiresAt)
		return err
	})
	return result, err
}

const importReceiptColumns = `id::text,deployment_id,environment,actor_user_id::text,encode(content_digest,'hex'),policy_generation,activation_generation,revision_id::text,revision_generation,expiration_days,total_rows,selected_rows,created_count,skipped_count,rejected_count,ARRAY(SELECT n::text FROM unnest(created_invitation_ids) n),created_at,completed_at,outcome,reason`

func scanImportReceipt(row pgx.Row) (ImportReceipt, error) {
	var r ImportReceipt
	err := row.Scan(&r.ID, &r.DeploymentID, &r.Environment, &r.ActorUserID, &r.ContentDigest, &r.PolicyGeneration, &r.ActivationGeneration, &r.RevisionID, &r.RevisionGeneration, &r.ExpirationDays, &r.Total, &r.SelectedRows, &r.Created, &r.Skipped, &r.Rejected, &r.InvitationIDs, &r.CreatedAt, &r.CompletedAt, &r.Outcome, &r.Reason)
	return r, err
}
func (r *AccessPolicyRepository) ReadInvitationImport(ctx context.Context, id string) (ImportReceipt, error) {
	var result ImportReceipt
	if err := requireImportOIDC(ctx); err != nil {
		return result, err
	}
	if !validID(id) {
		return result, ErrInvalid
	}
	err := adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		var err error
		result, err = scanImportReceipt(tx.QueryRow(ctx, `SELECT `+importReceiptColumns+` FROM framework.oidc_invitation_imports WHERE deployment_id=$1 AND environment=$2 AND id=$3`, r.scope.DeploymentID, r.scope.Environment, id))
		return err
	})
	return result, err
}

func (r *AccessPolicyRepository) ImportInvitationCSV(ctx context.Context, input CSVImportRequest) (ImportReceipt, error) {
	var result ImportReceipt
	if err := requireImportOIDC(ctx); err != nil {
		return result, err
	}
	expected := input.ImportExpectation.invitation()
	if !input.Confirm || !expected.valid() || !validID(input.ImportID) || !validID(input.IdempotencyKey) || !validPolicyReason(input.Reason) || utf8.RuneCountInString(strings.TrimSpace(input.Reason)) < 8 {
		return result, ErrInvalid
	}
	rows, err := parseInvitationCSV(input.CSV)
	if err != nil {
		return result, err
	}
	days, err := importDays(input.ExpirationDays)
	if err != nil {
		return result, err
	}
	input.ExpirationDays = days
	if len(input.SelectedRows) == 0 || len(input.SelectedRows) > len(rows) {
		return result, ErrInvalid
	}
	// Validate shape before receipt lookup. Eligibility is rechecked under the lock.
	for _, row := range input.SelectedRows {
		if row < 1 || row > len(rows) {
			return result, ErrInvalid
		}
	}
	proof, err := hex.DecodeString(input.PreviewDigest)
	if err != nil || len(proof) != 32 || input.PreviewExpiresAt.IsZero() {
		return result, ErrInvalid
	}
	input.ImportID = strings.ToLower(input.ImportID)
	input.IdempotencyKey = strings.ToLower(input.IdempotencyKey)
	canonical, err := json.Marshal(input)
	if err != nil {
		return result, ErrInvalid
	}
	payloadDigest := sha256.Sum256(canonical)
	keyDigest := sha256.Sum256([]byte(input.IdempotencyKey))
	contentDigest := sha256.Sum256([]byte(input.CSV))
	err = adminTransaction(ctx, r.store, func(ctx context.Context, tx pgx.Tx, actor access.User) error {
		var storedID string
		var storedDigest []byte
		err := tx.QueryRow(ctx, `SELECT id::text,payload_digest FROM framework.oidc_invitation_imports WHERE deployment_id=$1 AND environment=$2 AND (id=$3 OR (actor_user_id=$4 AND idempotency_digest=$5)) LIMIT 1`, r.scope.DeploymentID, r.scope.Environment, input.ImportID, actor.ID, keyDigest[:]).Scan(&storedID, &storedDigest)
		if err == nil {
			if storedID != input.ImportID || !hmac.Equal(storedDigest, payloadDigest[:]) {
				return ErrConflict
			}
			result, err = scanImportReceipt(tx.QueryRow(ctx, `SELECT `+importReceiptColumns+` FROM framework.oidc_invitation_imports WHERE deployment_id=$1 AND environment=$2 AND id=$3 AND actor_user_id=$4`, r.scope.DeploymentID, r.scope.Environment, storedID, actor.ID))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		b, err := r.invitationContext(ctx, tx, &expected)
		if err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if !now.Before(input.PreviewExpiresAt) {
			return ErrConflict
		}
		if err = r.classifyCSV(ctx, tx, b, rows, now); err != nil {
			return err
		}
		selected, err := selectedCSVRows(rows, input.SelectedRows, true)
		if err != nil {
			return err
		}
		digest, err := csvProof(ctx, tx, r.scope, actor.ID, input.CSVPreviewRequest, rows, selected, input.PreviewExpiresAt)
		if err != nil {
			return err
		}
		actual, _ := hex.DecodeString(digest)
		if !hmac.Equal(actual, proof) {
			return ErrConflict
		}
		ids := make([]string, 0, len(selected))
		expires := now.Add(time.Duration(days) * 24 * time.Hour)
		for _, index := range selected {
			row := rows[index-1]
			invitation, err := r.createInvitationTx(ctx, tx, actor, b, InvitationInput{Email: row.Email, DisplayName: row.DisplayName, ExpiresAt: &expires, Reason: input.Reason}, row.key, "csv", input.ImportID)
			if err != nil {
				return err
			}
			ids = append(ids, invitation.ID)
		}
		_, skipped, rejected := importSummary(rows, selected)
		result, err = scanImportReceipt(tx.QueryRow(ctx, `INSERT INTO framework.oidc_invitation_imports
   (id,deployment_id,environment,actor_user_id,idempotency_digest,content_digest,payload_digest,preview_digest,policy_generation,activation_generation,revision_id,revision_generation,issuer,client_id,expiration_days,total_rows,selected_rows,created_count,skipped_count,rejected_count,created_invitation_ids,created_at,outcome,reason)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'completed',$23) RETURNING `+importReceiptColumns,
			input.ImportID, r.scope.DeploymentID, r.scope.Environment, actor.ID, keyDigest[:], contentDigest[:], payloadDigest[:], proof, b.policy.Generation, b.activationGeneration, b.revision, b.revisionGeneration, b.issuer, b.client, days, len(rows), selected, len(ids), skipped, rejected, ids, now, input.Reason))
		if err != nil {
			return err
		}
		details := struct {
			Scope
			Created              int    `json:"created_count"`
			Skipped              int    `json:"skipped_count"`
			Rejected             int    `json:"rejected_count"`
			RevisionID           string `json:"revision_id"`
			PolicyGeneration     int64  `json:"policy_generation"`
			ActivationGeneration int64  `json:"activation_generation"`
			Reason               string `json:"reason"`
		}{r.scope, len(ids), skipped, rejected, b.revision, b.policy.Generation, b.activationGeneration, input.Reason}
		if access.RecordAudit(ctx, tx, actor.ID, "oidc_access.invitation_imported", result.ID, details) != nil {
			return ErrAudit
		}
		return nil
	})
	if err != nil {
		return ImportReceipt{}, err
	}
	return result, nil
}
