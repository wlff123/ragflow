package sensitive

import (
	"context"
	"strings"
	"time"
)

// CleanSegments detects values split across adjacent parser TextItems. Each
// segment retains its own surviving text; a crossing placeholder belongs only
// to the segment containing its start, preserving source-position ownership.
// Callers must not group separate table cells or structured records this way.
func (e *Engine) cleanSegments(ctx context.Context, segments []string, deadline time.Time) ([]string, Result, error) {
	text := strings.Join(segments, "")
	plan, err := e.replacementPlan(ctx, text, deadline)
	if err != nil {
		return nil, Result{}, err
	}
	runes := []rune(text)
	out := make([]string, len(segments))
	offset := 0
	next := 0
	for i, segment := range segments {
		end := offset + len([]rune(segment))
		pos := offset
		var b strings.Builder
		for next < len(plan) && plan[next].start < end {
			s := plan[next]
			if s.end <= offset {
				next++
				continue
			}
			if s.start >= offset {
				b.WriteString(string(runes[pos:s.start]))
				b.WriteString(placeholder(s.rule.Name))
			}
			pos = s.end
			if s.end > end {
				pos = end
				break
			}
			next++
		}
		b.WriteString(string(runes[pos:end]))
		out[i] = b.String()
		offset = end
	}
	cleaned := strings.Join(out, "")
	remaining, err := e.matches(ctx, cleaned, deadline)
	if err != nil {
		return nil, Result{}, err
	}
	if len(remaining) > 0 {
		return nil, Result{}, Failure("SP_RESCAN_HIT")
	}
	return out, Result{Text: cleaned, Count: int64(len(plan)), SourceCharacters: e.Characters(text), EffectiveCharacters: e.Characters(cleaned)}, nil
}
