// Package sanitization publishes shared text-sanitization fixture data.
//
// It performs no runtime work beyond decoding embedded JSON and is intended
// for tests only.
package sanitization

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Case is one sanitization expectation. Log and Label are the expected
// outputs of sanitize.Log and sanitize.Label for Input.
type Case struct {
	Name  string
	Input string
	Log   string
	Label string
}

type rawCase struct {
	Name     string  `json:"name"`
	Input    *string `json:"input"`
	InputHex *string `json:"input_hex"`
	Log      string  `json:"log"`
	Label    string  `json:"label"`
}

//go:embed cases.json
var casesJSON []byte

// Cases decodes the embedded fixtures. input_hex, when present, supplies raw
// bytes (for malformed UTF-8) and replaces input.
func Cases() ([]Case, error) {
	var raw []rawCase
	if err := json.Unmarshal(casesJSON, &raw); err != nil {
		return nil, fmt.Errorf("decode sanitization fixtures: %w", err)
	}
	out := make([]Case, 0, len(raw))
	for _, r := range raw {
		if r.Name == "" {
			return nil, fmt.Errorf("sanitization fixture without name")
		}
		if (r.Input == nil) == (r.InputHex == nil) {
			return nil, fmt.Errorf("sanitization fixture %q: exactly one of input or input_hex required", r.Name)
		}
		c := Case{Name: r.Name, Log: r.Log, Label: r.Label}
		if r.InputHex != nil {
			b, err := hex.DecodeString(*r.InputHex)
			if err != nil {
				return nil, fmt.Errorf("sanitization fixture %q: input_hex: %w", r.Name, err)
			}
			c.Input = string(b)
		} else {
			c.Input = *r.Input
		}
		out = append(out, c)
	}
	return out, nil
}
