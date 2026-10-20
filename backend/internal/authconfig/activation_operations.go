package authconfig

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/access"
	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/auth"
	"github.com/jackc/pgx/v5"
)

var (
	ErrActivationAffinityRequired = errors.New("auth_activation_affinity_required")
	ErrPreparationWrongInstance   = errors.New("auth_activation_preparation_wrong_instance")
)

type ActivationAffinity struct {
	Mode string `json:"mode"`
}

func ActivationAffinityFromEnv(getenv func(string) string) (ActivationAffinity, error) {
	mode := strings.TrimSpace(getenv("AUTH_ACTIVATION_AFFINITY_MODE"))
	switch mode {
	case "":
		return ActivationAffinity{}, nil
	case "single_instance", "session_affinity":
		return ActivationAffinity{Mode: mode}, nil
	default:
		return ActivationAffinity{}, ErrInvalid
	}
}

func (a ActivationAffinity) configured() bool {
	return a.Mode == "single_instance" || a.Mode == "session_affinity"
}

type ActivationOperations struct {
	Affinity              ActivationAffinity
	SynchronizationStatus func() SynchronizationStatus
	Reconcile             func(context.Context) error
}

type ActivationOperationalStatus struct {
	AuthoritativeSource      string        `json:"authoritative_source"`
	AuthoritativeGeneration  int64         `json:"authoritative_generation"`
	AuthoritativeRevisionID  string        `json:"authoritative_revision_id,omitempty"`
	LocalSource              string        `json:"local_source"`
	LocalProvider            auth.Provider `json:"local_provider"`
	LocalAppliedGeneration   int64         `json:"local_applied_generation"`
	LocalDesiredGeneration   int64         `json:"local_desired_generation"`
	LocalRevisionID          string        `json:"local_revision_id,omitempty"`
	TransitionDeadline       *time.Time    `json:"transition_deadline,omitempty"`
	ListenerConnected        bool          `json:"listener_connected"`
	SynchronizationDegraded  bool          `json:"synchronization_degraded"`
	Reconciled               bool          `json:"reconciled"`
	ReconciliationRequired   bool          `json:"reconciliation_required"`
	PreparationAffinityMode  string        `json:"preparation_affinity_mode,omitempty"`
	PreparationEnabled       bool          `json:"preparation_enabled"`
	AutomaticActivationRetry bool          `json:"automatic_activation_retry"`
}

func (r *Repository) activationHeadAuthorized(ctx context.Context) (ActivationHead, error) {
	head := ActivationHead{Scope: r.scope, RuntimeSource: "environment"}
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx, _ access.User) error {
		err := tx.QueryRow(ctx, `SELECT generation,runtime_source,COALESCE(active_revision_id::text,''),activated_at
 FROM framework.auth_activation_heads WHERE deployment_id=$1 AND environment=$2`, r.scope.DeploymentID, r.scope.Environment).
			Scan(&head.Generation, &head.RuntimeSource, &head.ActiveRevisionID, &head.ActivatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			head = ActivationHead{Scope: r.scope, RuntimeSource: "environment"}
			return nil
		}
		return err
	})
	return head, err
}

func (h *activationHTTP) operationalStatus(ctx context.Context) (ActivationOperationalStatus, error) {
	if h.service == nil {
		return ActivationOperationalStatus{}, ErrUnavailable
	}
	head, err := h.service.repo.activationHeadAuthorized(ctx)
	if err != nil {
		return ActivationOperationalStatus{}, err
	}
	local, desired, mismatch := h.service.runtime.ControlStatus()
	status := ActivationOperationalStatus{
		AuthoritativeSource: head.RuntimeSource, AuthoritativeGeneration: head.Generation,
		AuthoritativeRevisionID: head.ActiveRevisionID, LocalSource: local.Source,
		LocalProvider: local.Provider, LocalAppliedGeneration: local.AppliedGeneration,
		LocalDesiredGeneration: desired, LocalRevisionID: local.ActiveRevisionID,
		PreparationAffinityMode: h.operations.Affinity.Mode,
		PreparationEnabled:      h.operations.Affinity.configured(), AutomaticActivationRetry: false,
	}
	if !local.TransitionDeadline.IsZero() {
		deadline := local.TransitionDeadline
		status.TransitionDeadline = &deadline
	}
	if h.operations.SynchronizationStatus != nil {
		sync := h.operations.SynchronizationStatus()
		status.ListenerConnected = sync.Connected
		status.SynchronizationDegraded = sync.Degraded
		mismatch = mismatch || sync.Mismatched
	}
	status.Reconciled = !mismatch && head.Generation == local.AppliedGeneration && head.RuntimeSource == local.Source && head.ActiveRevisionID == local.ActiveRevisionID
	status.ReconciliationRequired = !status.Reconciled
	return status, nil
}
