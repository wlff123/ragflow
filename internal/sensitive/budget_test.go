package sensitive

import (
	"context"
	"testing"
	"time"
)

func TestBudgetCountsCleaningOnlyAndNestedCallsOnce(t *testing.T) {
	e := testEngine(t)
	ctx := e.WithBudget(context.Background())
	budget := ctx.Value(budgetKey{}).(*documentBudget)
	before := budget.remaining
	// Work outside a cleaning operation does not start a wall-clock deadline.
	if _, ok := ctx.Value(operationKey{}).(time.Time); ok {
		t.Fatal("document starts wall clock deadline")
	}
	_, err := budgeted(e, ctx, func(inner context.Context) (struct{}, error) {
		first := inner.Value(operationKey{})
		return budgeted(e, inner, func(nested context.Context) (struct{}, error) {
			if nested.Value(operationKey{}) != first {
				t.Fatal("nested budget renewed")
			}
			if budget.remaining != before {
				t.Fatal("nested operation debited early")
			}
			return struct{}{}, nil
		})
	})
	if err != nil || budget.remaining >= before {
		t.Fatalf("operation not accounted: %v", err)
	}
	after := budget.remaining
	if e.WithBudget(ctx) != ctx || budget.remaining != after {
		t.Fatal("budget reset")
	}
}

func TestSensitiveChunkScanChecksUnknownAndNestedFields(t *testing.T) {
	e := testEngine(t)
	for _, value := range []map[string]any{
		{"metadata": map[string]any{"phone": 13812345678}},
		{"new_field": "13812345678"},
		{"metadata": map[string]any{"id": "13812345678"}},
		{"q_4_vec": "13812345678"},
		{"img_id": "stored-image"},
	} {
		if err := e.ScanChunks(context.Background(), []map[string]any{value}); Reason(err) != "SP_RESCAN_HIT" {
			t.Fatalf("unsafe value accepted: %v", err)
		}
	}
	if err := e.ScanChunks(context.Background(), []map[string]any{{"text": "normal content", "q_2_vec": []float32{.1, .2}, "create_timestamp_flt": 1234567890123456.0}}); err != nil {
		t.Fatal(err)
	}
}

func TestSensitiveTypedBusinessFields(t *testing.T) {
	e := testEngine(t)
	clean, n, err := e.CleanValue(context.Background(), map[string]any{
		"labels":   []string{"normal", "13812345678"},
		"contacts": []map[string]any{{"phone": uint64(13812345678)}},
		"weights":  map[string]float64{"safe": 1},
	})
	if err != nil || n != 2 {
		t.Fatalf("typed business value failed: %d %v", n, err)
	}
	if err := e.ScanValue(context.Background(), clean); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.CleanValue(context.Background(), []byte("raw")); Reason(err) != "SP_STRUCTURE_INVALID" {
		t.Fatal("binary field admitted")
	}
}
