package sensitive

import "math"

const MaxPendingOperations = 128

type PendingOperation struct {
	Round string `json:"round"`
	Delta int64  `json:"delta"`
}

// Record contains only non-sensitive counters and server-generated identities.
// Mutating methods must be called while holding the owning document row lock.
type Record struct {
	Round               string                      `json:"pipeline_log_id"`
	RulesVersion        string                      `json:"rules_version"`
	SourceCharacters    int                         `json:"source_characters"`
	EffectiveCharacters int                         `json:"effective_characters"`
	BaseCount           int64                       `json:"base_count"`
	ManualCount         int64                       `json:"manual_count"`
	Confirmed           bool                        `json:"confirmed"`
	FailureReason       string                      `json:"failure_reason"`
	Uncertain           bool                        `json:"uncertain"`
	Pending             map[string]PendingOperation `json:"pending,omitempty"`
}

// Begin resets only a new business run. Pending operations survive reparsing.
func (r *Record) Begin(round string) error {
	if round == "" {
		return Failure("SP_RESULT_SAVE_FAILED")
	}
	if r.Round == round {
		return nil
	}
	pending := r.Pending
	*r = Record{Round: round, Pending: pending, Uncertain: len(pending) > 0}
	return nil
}

func (r *Record) Confirm(round, version string, result Result) error {
	if round == "" || round != r.Round || version == "" || result.Count < 0 {
		return Failure("SP_RESULT_SAVE_FAILED")
	}
	if r.FailureReason != "" {
		return Failure(r.FailureReason)
	}
	if r.Confirmed && (r.BaseCount != result.Count || r.RulesVersion != version || r.SourceCharacters != result.SourceCharacters || r.EffectiveCharacters != result.EffectiveCharacters) {
		r.Uncertain = true
	}
	r.BaseCount = result.Count
	r.RulesVersion = version
	r.SourceCharacters = result.SourceCharacters
	r.EffectiveCharacters = result.EffectiveCharacters
	r.Confirmed = true
	return nil
}

func (r *Record) Fail(round, reason string) error {
	if round == "" || round != r.Round {
		return Failure("SP_RESULT_SAVE_FAILED")
	}
	if reason == "" {
		return Failure("SP_CONFIG_INVALID")
	}
	r.FailureReason = reason
	r.Confirmed = false
	return nil
}

func (r *Record) Count() *int64 {
	if !r.Confirmed || r.FailureReason != "" || r.Uncertain || len(r.Pending) > 0 || r.BaseCount < 0 || r.ManualCount < 0 || r.BaseCount > math.MaxInt64-r.ManualCount {
		return nil
	}
	n := r.BaseCount + r.ManualCount
	return &n
}

func (r *Record) Register(id string, delta int64) error {
	if !r.Confirmed || r.FailureReason != "" || r.Round == "" {
		return Failure("SP_NOT_PROCESSED")
	}
	if id == "" || delta < 0 || len(r.Pending) >= MaxPendingOperations {
		return Failure("SP_RESULT_SAVE_FAILED")
	}
	if r.Pending == nil {
		r.Pending = map[string]PendingOperation{}
	}
	if _, ok := r.Pending[id]; ok {
		return Failure("SP_RESULT_SAVE_FAILED")
	}
	r.Pending[id] = PendingOperation{Round: r.Round, Delta: delta}
	return nil
}

// Finish is idempotent for an internal retry of the same operation. Only an
// explicitly successful write counts; unknown outcomes leave their marker.
func (r *Record) Finish(id string, written bool) {
	op, ok := r.Pending[id]
	if !ok {
		return
	}
	if op.Round != r.Round {
		if written {
			r.Uncertain = true
		}
	} else if written {
		if op.Delta < 0 || r.ManualCount > math.MaxInt64-op.Delta {
			r.Uncertain = true
		} else {
			r.ManualCount += op.Delta
		}
	}
	delete(r.Pending, id)
}
