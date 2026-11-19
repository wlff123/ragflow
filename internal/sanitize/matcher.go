//
//  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

package sanitize

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/dlclark/regexp2"
)

// matchTimeout bounds a single regexp2 match call. The rules contain
// lookarounds and unbounded quantifiers, so a pathological input must fail
// with ErrTimeout instead of stalling the caller.
const matchTimeout = 10 * time.Second

// compiledRule is a validated rule with its compiled expression. order is the
// rule's position in the catalog and breaks priority ties deterministically.
type compiledRule struct {
	rule
	re    *regexp2.Regexp
	order int
}

// span is a half-open rune range [start, end) to replace with rule's placeholder.
type span struct {
	start, end int
	rule       *compiledRule
}

// compileRules compiles every pattern before any rule becomes usable. A rule
// that matches the empty string, or that matches any standard placeholder,
// would break replacement or idempotency and is rejected.
func compileRules(c *catalog) ([]*compiledRule, map[string]bool, error) {
	rules := make([]*compiledRule, 0, len(c.Rules))
	placeholders := make(map[string]bool, len(c.Rules))
	for i, r := range c.Rules {
		re, err := regexp2.Compile(r.Pattern, regexp2.None)
		if err != nil {
			return nil, nil, ErrRulesUnavailable
		}
		re.MatchTimeout = matchTimeout
		if hit, err := re.MatchString(""); err != nil || hit {
			return nil, nil, ErrRulesUnavailable
		}
		rules = append(rules, &compiledRule{rule: r, re: re, order: i})
		placeholders[placeholder(r.Name)] = true
	}
	for p := range placeholders {
		for _, r := range rules {
			if hit, err := r.re.MatchString(p); err != nil || hit {
				return nil, nil, ErrRulesUnavailable
			}
		}
	}
	return rules, placeholders, nil
}

// findSpans returns every rule match in runes (which must already have
// placeholders masked). Spans of different rules may overlap; resolveSpans
// turns them into the final replacement plan.
func findSpans(ctx context.Context, rules []*compiledRule, runes []rune) ([]span, error) {
	var found []span
	for _, r := range rules {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		m, err := r.re.FindRunesMatch(runes)
		for m != nil && err == nil {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
			s := span{start: m.Index, end: m.Index + m.Length, rule: r}
			if r.Scope == scopeValueAfterSeparator {
				s = valueSpan(runes, s)
			}
			if s.end > s.start {
				found = append(found, s)
			}
			m, err = r.re.FindNextMatch(m)
		}
		if err != nil {
			// regexp2 reports timeouts as plain errors whose text includes the
			// input; never propagate it.
			return nil, ErrTimeout
		}
	}
	return found, nil
}

// valueSpan narrows a key/value match to its value: it skips the key up to the
// first ':' or '=' (also "=:" and "=>"), then spaces and quotes, and covers the
// value characters that follow. The key, separator and quotes are kept, so
// "password: abc" keeps "password: " and JSON/YAML syntax stays intact. An
// empty result (no value) yields start == end and is dropped by the caller.
func valueSpan(runes []rune, s span) span {
	i := s.start
	for i < s.end && runes[i] != ':' && runes[i] != '=' {
		i++
	}
	if i >= s.end {
		return span{start: s.start, end: s.start, rule: s.rule}
	}
	if runes[i] == '=' && i+1 < s.end && (runes[i+1] == ':' || runes[i+1] == '>') {
		i++
	}
	i++
	for i < s.end && (unicode.IsSpace(runes[i]) || runes[i] == '\'' || runes[i] == '"') {
		i++
	}
	end := i
	for end < len(runes) && isValueRune(runes[end]) {
		end++
	}
	return span{start: i, end: end, rule: s.rule}
}

// isValueRune is the value character class of the key/value rule:
// [A-Za-z0-9_+\-/=].
func isValueRune(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("_+-/=", r)
}

// checkContext maps a cancelled context to the caller's error and an expired
// deadline to ErrTimeout.
func checkContext(ctx context.Context) error {
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return err
}
