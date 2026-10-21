package authconfig

import (
	"encoding/csv"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const CSVMaxBytes = 1 << 20
const CSVMaxRows = 500

var (
	ErrCSVFormat = errors.New("oidc_import_invalid_csv")
	ErrCSVSize   = errors.New("oidc_import_file_too_large")
	ErrCSVRows   = errors.New("oidc_import_too_many_rows")
	ErrCSVEmpty  = errors.New("oidc_import_empty")
)

type CSVRow struct {
	Row         int    `json:"row"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	key         string
}

// encoding/csv owns quoting and LF/CRLF parsing. Never trim or fold mailbox
// local parts. Row numbers identify logical records, including quoted fields.
func parseInvitationCSV(contents string) ([]CSVRow, error) {
	if len(contents) > CSVMaxBytes {
		return nil, ErrCSVSize
	}
	if !utf8.ValidString(contents) {
		return nil, ErrCSVFormat
	}
	text := strings.TrimPrefix(contents, "\ufeff")
	reader := csv.NewReader(strings.NewReader(text))
	header, err := reader.Read()
	if errors.Is(err, io.EOF) {
		return nil, ErrCSVEmpty
	}
	if err != nil || len(header) < 1 || len(header) > 2 {
		return nil, ErrCSVFormat
	}
	headerLine, _ := reader.FieldPos(0)
	if headerLine != 1 {
		return nil, ErrCSVFormat
	}
	emailColumn, nameColumn := -1, -1
	for n, h := range header {
		switch h {
		case "email":
			if emailColumn != -1 {
				return nil, ErrCSVFormat
			}
			emailColumn = n
		case "display_name":
			if nameColumn != -1 {
				return nil, ErrCSVFormat
			}
			nameColumn = n
		default:
			return nil, ErrCSVFormat
		}
	}
	if emailColumn < 0 {
		return nil, ErrCSVFormat
	}
	reader.FieldsPerRecord = len(header)
	rows := []CSVRow{}
	duplicates := map[string]int{}
	for {
		// encoding/csv skips empty physical lines. Treat those outside quoted fields
		// as explicit invalid-email rows instead of silently omitting employees.
		offset := int(reader.InputOffset())
		for offset < len(text) {
			width := 0
			if text[offset] == '\n' {
				width = 1
			} else if strings.HasPrefix(text[offset:], "\r\n") {
				width = 2
			}
			if width == 0 {
				break
			}
			if len(rows) == CSVMaxRows {
				return nil, ErrCSVRows
			}
			rows = append(rows, CSVRow{Row: len(rows) + 1, Status: "invalid_email"})
			offset += width
		}
		fields, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, ErrCSVFormat
		}
		if len(rows) == CSVMaxRows {
			return nil, ErrCSVRows
		}
		row := CSVRow{Row: len(rows) + 1, Email: fields[emailColumn], Status: "ready"}
		if nameColumn >= 0 {
			row.DisplayName = fields[nameColumn]
		}
		row.key, err = invitationEmailKey(row.Email)
		if err != nil {
			row.Status = "invalid_email"
		} else {
			duplicates[strings.ToLower(row.key)]++
		}
		if row.Status == "ready" && (utf8.RuneCountInString(row.DisplayName) > 200 || strings.ContainsFunc(row.DisplayName, unicode.IsControl)) {
			row.Status = "invalid_display_name"
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, ErrCSVEmpty
	}
	for n := range rows {
		if rows[n].Status == "ready" && duplicates[strings.ToLower(rows[n].key)] > 1 {
			rows[n].Status = "duplicate_csv"
		}
	}
	return rows, nil
}

func selectedCSVRows(rows []CSVRow, requested []int, requireSelection bool) ([]int, error) {
	if requested == nil && !requireSelection {
		requested = []int{}
		for _, row := range rows {
			if row.Status == "ready" {
				requested = append(requested, row.Row)
			}
		}
	}
	if len(requested) > len(rows) || (requireSelection && len(requested) == 0) {
		return nil, ErrInvalid
	}
	selected := append([]int{}, requested...)
	sort.Ints(selected)
	for n, row := range selected {
		if row < 1 || row > len(rows) || (n > 0 && selected[n-1] == row) {
			return nil, ErrInvalid
		}
		if rows[row-1].Status != "ready" {
			return nil, ErrConflict
		}
	}
	return selected, nil
}
