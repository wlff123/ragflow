package sensitive

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialListsRetainFieldContext(t *testing.T) {
	e := testEngine(t)
	for name, values := range map[string]any{
		"list":    []any{"abcdefgh1234"},
		"nested":  []any{[]any{"abcdefgh1234"}},
		"typed":   []string{"abcdefgh1234"},
		"array":   [1]string{"abcdefgh1234"},
		"numeric": []any{json.Number("12345678")},
	} {
		t.Run(name, func(t *testing.T) {
			input := map[string]any{"password": values}
			if err := e.ScanValue(t.Context(), input); err == nil {
				t.Fatal("raw credential list passed scan")
			}
			clean, count, err := e.CleanValue(t.Context(), input)
			if err != nil || count != 1 {
				t.Fatalf("count=%d err=%v", count, err)
			}
			if err := e.ScanValue(t.Context(), clean); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, input := range []string{`{"password":[["abcdefgh1234"]]}`, `{"password":[12345678]}`} {
		r, err := e.CleanJSON(t.Context(), input)
		if err != nil || r.Count != 1 || !strings.Contains(r.Text, "[敏感信息已移除：密钥类]") {
			t.Fatalf("JSON: %+v %v", r, err)
		}
	}
	r, err := e.CleanYAML(t.Context(), "password:\n  - [abcdefgh1234]\n")
	if err != nil || r.Count != 1 || !strings.Contains(r.Text, "[敏感信息已移除：密钥类]") {
		t.Fatalf("YAML: %+v %v", r, err)
	}
	// A nested mapping supplies its own semantic keys.
	_, count, err := e.CleanValue(t.Context(), map[string]any{"password": []any{map[string]any{"description": "abcdefgh1234"}}})
	if err != nil || count != 0 {
		t.Fatalf("nested mapping: %d %v", count, err)
	}
}
