package authconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// Only these CSV endpoints accept a larger envelope. One CSV byte can require
// six JSON bytes; the decoded CSV still has an independent strict 1 MiB limit.
const importJSONLimit = 6*CSVMaxBytes + 32*1024

func validJSONUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for n := 0; n < len(data); n++ {
		if data[n] != '"' {
			continue
		}
		n++
		for n < len(data) && data[n] != '"' {
			if data[n] != '\\' {
				n++
				continue
			}
			if n+1 >= len(data) {
				return false
			}
			if data[n+1] != 'u' {
				n += 2
				continue
			}
			if n+6 > len(data) {
				return false
			}
			code, err := strconv.ParseUint(string(data[n+2:n+6]), 16, 16)
			if err != nil {
				return false
			}
			n += 6
			if code >= 0xd800 && code <= 0xdbff {
				if n+6 > len(data) || data[n] != '\\' || data[n+1] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(data[n+2:n+6]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				n += 6
			} else if code >= 0xdc00 && code <= 0xdfff {
				return false
			}
		}
	}
	return true
}
func decodeImportJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	body := http.MaxBytesReader(w, r.Body, importJSONLimit)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			reply(w, 413, map[string]string{"error": "oidc_import_file_too_large"})
		} else {
			reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
		}
		return false
	}
	if !validJSONUnicode(data) {
		reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
		return false
	}
	// Reject duplicate top-level keys as well as unknown fields and trailing JSON.
	probe := json.NewDecoder(bytes.NewReader(data))
	token, err := probe.Token()
	if err != nil || token != json.Delim('{') {
		reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
		return false
	}
	allowed := map[string]bool{}
	for _, key := range []string{"csv", "selected_rows", "expiration_days", "expected_policy_generation", "expected_activation_generation", "revision_id", "expected_revision_generation"} {
		allowed[key] = true
	}
	if _, ok := value.(*CSVImportRequest); ok {
		for _, key := range []string{"import_id", "idempotency_key", "preview_digest", "preview_expires_at", "reason", "confirm"} {
			allowed[key] = true
		}
	}
	seen := map[string]bool{}
	for probe.More() {
		token, err = probe.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !allowed[key] {
			reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
			return false
		}
		seen[key] = true
		var discard json.RawMessage
		if probe.Decode(&discard) != nil {
			reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		reply(w, 400, map[string]string{"error": "oidc_import_invalid_csv"})
		return false
	}
	return true
}
func invitationImportError(w http.ResponseWriter, err error, id string) {
	status, code := 503, "oidc_import_unavailable"
	switch {
	case errors.Is(err, ErrCSVSize):
		status, code = 413, ErrCSVSize.Error()
	case errors.Is(err, ErrCSVRows):
		status, code = 400, ErrCSVRows.Error()
	case errors.Is(err, ErrCSVEmpty):
		status, code = 400, ErrCSVEmpty.Error()
	case errors.Is(err, ErrCSVFormat), errors.Is(err, ErrInvalid):
		status, code = 400, "oidc_import_invalid_csv"
	case errors.Is(err, ErrDenied):
		status, code = 403, "oidc_import_denied"
	case errors.Is(err, ErrNotFound):
		status, code = 404, "oidc_import_receipt_not_found"
	case errors.Is(err, ErrConflict):
		status, code = 409, "oidc_import_conflict"
	case errors.Is(err, ErrCommitUncertain):
		code = "oidc_import_commit_uncertain"
	}
	body := map[string]any{"error": code}
	if status >= 500 && validID(id) {
		body["import_id"] = id
		body["inspection_required"] = true
		body["automatic_retry_allowed"] = false
	}
	reply(w, status, body)
}
func registerInvitationImportRoutes(route func(string, http.HandlerFunc), repo *AccessPolicyRepository) {
	base := accessPolicyPath + "/invitations"
	route("POST "+base+"/import/preview", func(w http.ResponseWriter, r *http.Request) {
		if err := requireImportOIDC(r.Context()); err != nil {
			invitationImportError(w, err, "")
			return
		}
		var body CSVPreviewRequest
		if !decodeImportJSON(w, r, &body) {
			return
		}
		result, err := repo.PreviewInvitationCSV(r.Context(), body)
		if err != nil {
			invitationImportError(w, err, "")
			return
		}
		reply(w, 200, result)
	})
	route("POST "+base+"/import", func(w http.ResponseWriter, r *http.Request) {
		if err := requireImportOIDC(r.Context()); err != nil {
			invitationImportError(w, err, "")
			return
		}
		var body CSVImportRequest
		if !decodeImportJSON(w, r, &body) {
			return
		}
		result, err := repo.ImportInvitationCSV(r.Context(), body)
		if err != nil {
			invitationImportError(w, err, body.ImportID)
			return
		}
		reply(w, 200, result)
	})
	route("GET "+base+"/imports/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, err := repo.ReadInvitationImport(r.Context(), r.PathValue("id"))
		if err != nil {
			invitationImportError(w, err, "")
			return
		}
		reply(w, 200, result)
	})
}
