package format

import (
	"encoding/json"

	"github.com/Leathal1/TITO/pkg/diff"
)

// FormatJSON generates a machine-readable JSON output
func FormatJSON(d *diff.DiffResult) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// FormatJSONCompact generates a compact JSON output
func FormatJSONCompact(d *diff.DiffResult) ([]byte, error) {
	return json.Marshal(d)
}
