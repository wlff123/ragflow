package sensitive

import (
	"context"
	"sync"
	"time"
)

type budgetKey struct{}
type operationKey struct{}
type documentBudget struct {
	mu        sync.Mutex
	remaining time.Duration
}

// WithBudget gives one document a shared cleaning-time allowance. Waiting for
// storage, parsing or a model does not consume regex processing time.
func (e *Engine) WithBudget(ctx context.Context) context.Context {
	if _, ok := ctx.Value(budgetKey{}).(*documentBudget); ok {
		return ctx
	}
	return context.WithValue(ctx, budgetKey{}, &documentBudget{remaining: e.budget})
}

func (e *Engine) deadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Value(operationKey{}).(time.Time); ok {
		return deadline
	}
	return time.Now().Add(e.budget)
}

// budgeted accounts a nested operation only once. Parallel jobs debit the same
// allowance; a job that exhausts it fails even when its own last scan succeeded.
func budgeted[T any](e *Engine, ctx context.Context, run func(context.Context) (T, error)) (result T, err error) {
	if _, ok := ctx.Value(operationKey{}).(time.Time); ok {
		return run(ctx)
	}
	ctx = e.WithBudget(ctx)
	budget := ctx.Value(budgetKey{}).(*documentBudget)
	budget.mu.Lock()
	remaining := budget.remaining
	budget.mu.Unlock()
	if remaining <= 0 {
		return result, Failure("SP_REGEX_TIMEOUT")
	}
	start := time.Now()
	ctx = context.WithValue(ctx, operationKey{}, start.Add(remaining))
	result, err = run(ctx)
	budget.mu.Lock()
	budget.remaining -= time.Since(start)
	exhausted := budget.remaining <= 0
	budget.mu.Unlock()
	if exhausted && err == nil {
		var zero T
		return zero, Failure("SP_REGEX_TIMEOUT")
	}
	return result, err
}

func (e *Engine) Clean(ctx context.Context, text string) (Result, error) {
	return budgeted(e, ctx, func(ctx context.Context) (Result, error) { return e.clean(ctx, text, e.deadline(ctx)) })
}
func (e *Engine) Scan(ctx context.Context, text string) error {
	_, err := budgeted(e, ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, e.scanText(ctx, text) })
	return err
}
func (e *Engine) CleanJSON(ctx context.Context, text string) (Result, error) {
	return budgeted(e, ctx, func(ctx context.Context) (Result, error) { return e.cleanJSON(ctx, text) })
}
func (e *Engine) CleanYAML(ctx context.Context, text string) (Result, error) {
	return budgeted(e, ctx, func(ctx context.Context) (Result, error) { return e.cleanYAML(ctx, text) })
}
func (e *Engine) CleanValue(ctx context.Context, value any) (any, int64, error) {
	type valueResult struct {
		value any
		count int64
	}
	result, err := budgeted(e, ctx, func(ctx context.Context) (valueResult, error) {
		v, n, err := e.cleanBusinessValue(ctx, value)
		return valueResult{v, n}, err
	})
	return result.value, result.count, err
}
func (e *Engine) CleanSegments(ctx context.Context, segments []string) ([]string, Result, error) {
	type segmentResult struct {
		parts  []string
		result Result
	}
	result, err := budgeted(e, ctx, func(ctx context.Context) (segmentResult, error) {
		parts, r, err := e.cleanSegments(ctx, segments, e.deadline(ctx))
		return segmentResult{parts, r}, err
	})
	return result.parts, result.result, err
}
