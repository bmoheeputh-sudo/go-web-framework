package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/bmoheeputh-sudo/go-web-framework/backend/internal/authconfig"
)

type fakeWorkflow struct {
	preview                authconfig.RecoveryPreview
	result                 authconfig.RecoveryResult
	prepareErr, recoverErr error
	recovered              bool
}

func (f *fakeWorkflow) Prepare(context.Context, string, int64, string) (authconfig.RecoveryPreview, error) {
	return f.preview, f.prepareErr
}
func (f *fakeWorkflow) Recover(context.Context) (authconfig.RecoveryResult, error) {
	f.recovered = true
	return f.result, f.recoverErr
}
func (*fakeWorkflow) Close() {}

func recoveryEnvironment(t *testing.T) func(string) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	clear(key)
	return func(name string) string {
		return map[string]string{
			"AUTH_CONFIG_DEPLOYMENT": "installation-a", "APP_ENV": "development",
			"AUTH_RECOVERY_ENABLED": "true", "AUTH_RECOVERY_OPERATOR_ID": "ops@example.test",
			"AUTH_RECOVERY_AUTHORIZATION_KEY_ID": "recovery-v1", "AUTH_RECOVERY_AUTHORIZATION_KEY": encoded,
		}[name]
	}
}

func TestRecoveryCLIRequiresExactPreviewConfirmation(t *testing.T) {
	const revision = "11111111-1111-4111-8111-111111111111"
	preview := authconfig.RecoveryPreview{Scope: authconfig.Scope{DeploymentID: "installation-a", Environment: "development"}, OperatorID: "ops@example.test", AuthorizationKeyID: "recovery-v1", CurrentRevisionID: "22222222-2222-4222-8222-222222222222", TargetRevisionID: revision, SourceRevisionID: "33333333-3333-4333-8333-333333333333", ExpectedGeneration: 2, TargetGeneration: 3, IssuerURL: "https://issuer.example.test", ClientID: "client", Reason: "incident INC-123", RequiresReauthentication: true}
	args := []string{"--deployment", "installation-a", "--environment", "development", "--expected-generation", "2", "--revision", revision, "--reason", "incident INC-123"}
	for _, tc := range []struct {
		name, input string
		recovered   bool
	}{
		{"empty", "", false}, {"wrong", "yes\n", false},
		{"exact", "RECOVER installation-a/development GENERATION 3 REVISION " + revision + "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeWorkflow{preview: preview, result: authconfig.RecoveryResult{Generation: 3, RevisionID: revision, Committed: true}}
			var output bytes.Buffer
			getenv := recoveryEnvironment(t)
			err := run(args, getenv, strings.NewReader(tc.input), &output, func(context.Context, func(string) string, *authconfig.OfflineOperator) (workflow, error) {
				return fake, nil
			})
			if (err == nil) != tc.recovered || fake.recovered != tc.recovered {
				t.Fatal("unexpected confirmation result", err)
			}
			if strings.Contains(output.String(), "AUTH_RECOVERY") || strings.Contains(output.String(), "AUTH_ENCRYPTION") || strings.Contains(output.String(), getenv("AUTH_RECOVERY_AUTHORIZATION_KEY")) {
				t.Fatal("secret setting leaked")
			}
		})
	}
}

func TestRecoveryCLIRejectsUnauthorizedOrMismatchedScopeBeforeDatabase(t *testing.T) {
	args := []string{"--deployment", "other", "--environment", "development", "--expected-generation", "1", "--revision", "11111111-1111-4111-8111-111111111111", "--reason", "incident INC-123"}
	opened := false
	err := run(args, recoveryEnvironment(t), strings.NewReader(""), io.Discard, func(context.Context, func(string) string, *authconfig.OfflineOperator) (workflow, error) {
		opened = true
		return nil, errors.New("unexpected")
	})
	if err == nil || opened {
		t.Fatal("scope mismatch reached database")
	}
	getenv := recoveryEnvironment(t)
	err = run([]string{"--deployment", "installation-a", "--environment", "development", "--expected-generation", "1", "--revision", "11111111-1111-4111-8111-111111111111", "--reason", "incident INC-123"}, func(name string) string {
		if name == "AUTH_RECOVERY_ENABLED" {
			return ""
		}
		return getenv(name)
	}, strings.NewReader(""), io.Discard, func(context.Context, func(string) string, *authconfig.OfflineOperator) (workflow, error) {
		opened = true
		return nil, nil
	})
	if err == nil || opened {
		t.Fatal("unauthorized operator reached database")
	}
}
