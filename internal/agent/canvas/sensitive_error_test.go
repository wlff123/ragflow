package canvas

import (
	"context"
	"testing"

	"ragflow/internal/sensitive"
)

func TestSensitiveErrorCannotUseExceptionFallback(t *testing.T) {
	for _, params := range []map[string]any{
		{"exception_method": "comment", "exception_default_value": "unsafe fallback"},
		{"exception_method": "goto", "exception_goto": []string{"next"}},
	} {
		err := sensitive.Failure("SP_RESCAN_HIT")
		body := withExceptionHandler("parser", params, func(context.Context, map[string]any) (map[string]any, error) { return nil, err })
		out, got := body(context.Background(), map[string]any{})
		if got != err || out != nil {
			t.Fatalf("safety error swallowed: out=%v err=%v", out, got)
		}
	}
}
