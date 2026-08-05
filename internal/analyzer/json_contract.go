package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// decodeStrictJSONObject decodes exactly one JSON object. Model responses are
// untrusted: prose wrappers, trailing values, and unknown fields are rejected
// instead of being heuristically stripped or silently ignored.
func decodeStrictJSONObject(raw string, dst any) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty JSON response")
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		// Decoder diagnostics can echo attacker/model-controlled unknown field
		// names. Keep the public error categorical so a reflected credential cannot
		// escape through logs while preserving a strict fail-closed contract.
		return fmt.Errorf("invalid JSON object or response schema")
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value after response object")
		}
		return fmt.Errorf("trailing data after response object: %w", err)
	}
	return nil
}
