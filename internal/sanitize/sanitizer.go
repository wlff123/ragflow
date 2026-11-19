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

// Package sanitize removes sensitive values from text and writes typed
// placeholders in their place, following the "知识库敏感信息统一清除与占位符规范"
// requirement (chapter 7 rules, chapter 8 replacement rules).
//
// The package holds the business rules only and has no dependency on the
// ingestion pipeline, storage or HTTP layers, so any module of the repository
// can reuse it. It never logs: results and errors carry rule ids and counts,
// never source text.
package sanitize

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

// envRulesPath names an optional external rule file that replaces the
// built-in rules. See Default.
const envRulesPath = "RAGFLOW_SANITIZE_RULES_PATH"

// Sanitizer finds and replaces sensitive values. It is immutable and safe for
// concurrent use.
type Sanitizer struct {
	rules        []*compiledRule
	placeholders map[string]bool
	info         RulesInfo
}

// Result is the outcome of one Sanitize call.
type Result struct {
	// Text is the sanitized text; equal to the input when Count is 0.
	Text string
	// Count is the number of placeholders written: overlapping hits and
	// adjacent hits of the same rule count once each.
	Count int
	// RuleHits counts placeholders per rule id. Nil when Count is 0.
	RuleHits map[string]int
}

// Add accumulates the counts of o into r; r.Text is left untouched.
func (r *Result) Add(o Result) {
	if o.Count == 0 {
		return
	}
	r.Count += o.Count
	if r.RuleHits == nil {
		r.RuleHits = make(map[string]int, len(o.RuleHits))
	}
	for id, n := range o.RuleHits {
		r.RuleHits[id] += n
	}
}

// RulesInfo describes a loaded rule set.
type RulesInfo struct {
	Version string // catalog_version of the rule file
	Source  string // SourceBuiltin or SourceExternal
}

var (
	defaultOnce sync.Once
	defaultSan  *Sanitizer
	defaultErr  error
)

// Default returns the process-wide Sanitizer, loading it on first use.
//
// Without RAGFLOW_SANITIZE_RULES_PATH it uses the built-in rules embedded in the
// binary. With RAGFLOW_SANITIZE_RULES_PATH set, the file it names replaces the
// built-in rules; it must keep the same 20 rule ids, display names and scopes.
// A missing or invalid external file fails with ErrRulesUnavailable and never
// falls back to the built-in rules. The result, including a failure, is cached
// for the life of the process.
func Default() (*Sanitizer, error) {
	defaultOnce.Do(func() {
		defaultSan, defaultErr = loadDefault(os.Getenv)
	})
	return defaultSan, defaultErr
}

// loadDefault is Default without the process-wide cache.
func loadDefault(getenv func(string) string) (*Sanitizer, error) {
	path := strings.TrimSpace(getenv(envRulesPath))
	if path == "" {
		base, err := builtinCatalog()
		if err != nil {
			return nil, err
		}
		return newSanitizer(base, SourceBuiltin)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRulesUnavailable
	}
	defer f.Close()
	return newFromReader(f)
}

// newFromReader builds a Sanitizer from an external rule file. The file must
// keep the built-in rule set (same ids, display names and scopes); patterns,
// priorities and the catalog version may differ.
func newFromReader(r io.Reader) (*Sanitizer, error) {
	base, err := builtinCatalog()
	if err != nil {
		return nil, err
	}
	c, err := decodeCatalog(r)
	if err != nil {
		return nil, err
	}
	if !c.conformsTo(base) {
		return nil, ErrRulesUnavailable
	}
	return newSanitizer(c, SourceExternal)
}

func newSanitizer(c *catalog, source string) (*Sanitizer, error) {
	rules, placeholders, err := compileRules(c)
	if err != nil {
		return nil, err
	}
	return &Sanitizer{rules: rules, placeholders: placeholders, info: RulesInfo{Version: c.Version, Source: source}}, nil
}

// Rules describes the loaded rule set.
func (s *Sanitizer) Rules() RulesInfo { return s.info }

// Sanitize replaces every sensitive value in text with its placeholder, then
// re-checks the result. It returns ErrResidual if a rule still matches,
// ErrTimeout on a regex timeout or an expired ctx deadline, and ctx.Err() when
// ctx is cancelled. Existing standard placeholders are left untouched, so
// Sanitize is idempotent. A complete JSON object or array is matched on its
// decoded values (see sanitizeJSON) and stays valid JSON.
func (s *Sanitizer) Sanitize(ctx context.Context, text string) (Result, error) {
	if isJSONDocument(text) {
		return s.sanitizeJSONDocument(ctx, text)
	}
	r, err := s.sanitizeText(ctx, text)
	if err != nil || r.Count == 0 {
		// Nothing matched: the text is returned unchanged, and re-checking it
		// would repeat exactly the scan that just found nothing.
		return r, err
	}
	return r, s.checkResidual(ctx, r.Text)
}

// sanitizeJSONDocument sanitizes a JSON document value by value and re-checks
// the result the same way. The raw text is never matched as a whole: escapes
// would hide values from it, and a match spanning several tokens would
// rewrite JSON syntax.
func (s *Sanitizer) sanitizeJSONDocument(ctx context.Context, text string) (Result, error) {
	r, err := s.sanitizeJSON(ctx, text)
	if err != nil || r.Count == 0 {
		return r, err
	}
	again, err := s.sanitizeJSON(ctx, r.Text)
	if err != nil {
		return Result{}, err
	}
	if again.Count > 0 {
		return Result{}, ErrResidual
	}
	return r, nil
}

// SanitizeField sanitizes value as the value of key, the way a structured
// record (a map, a JSON object) holds it. The value is matched as
// "key: value", so key/value rules such as 密钥类 apply to it; replacements
// stay inside the value. With an empty key, or when value is itself a JSON
// document, it is the same as Sanitize.
func (s *Sanitizer) SanitizeField(ctx context.Context, key, value string) (Result, error) {
	if key == "" || isJSONDocument(value) {
		return s.Sanitize(ctx, value)
	}
	r, err := s.sanitizeKeyed(ctx, key, value)
	if err != nil || r.Count == 0 {
		return r, err
	}
	residual, _, err := s.keyedPlan(ctx, key, r.Text)
	if err != nil {
		return Result{}, err
	}
	if len(residual) > 0 {
		return Result{}, ErrResidual
	}
	return r, nil
}

// sanitizeText is the plain-text pass: match, resolve, render.
func (s *Sanitizer) sanitizeText(ctx context.Context, text string) (Result, error) {
	runes := []rune(text)
	plan, err := s.plan(ctx, text, runes)
	if err != nil {
		return Result{}, err
	}
	if len(plan) == 0 {
		return Result{Text: text}, nil
	}
	out, hits := render(runes, plan)
	return Result{Text: out, Count: len(plan), RuleHits: hits}, nil
}

// sanitizeKeyed replaces the hits of the keyed plan inside value.
func (s *Sanitizer) sanitizeKeyed(ctx context.Context, key, value string) (Result, error) {
	plan, valueRunes, err := s.keyedPlan(ctx, key, value)
	if err != nil {
		return Result{}, err
	}
	if len(plan) == 0 {
		return Result{Text: value}, nil
	}
	out, hits := render(valueRunes, plan)
	return Result{Text: out, Count: len(plan), RuleHits: hits}, nil
}

// keyedPlan plans "key: value" and returns the spans that touch the value,
// shifted to index the returned value runes. Hits entirely inside the key are
// dropped: the key is sanitized as text of its own.
func (s *Sanitizer) keyedPlan(ctx context.Context, key, value string) ([]span, []rune, error) {
	prefix := key + ": "
	full := prefix + value
	runes := []rune(full)
	plan, err := s.plan(ctx, full, runes)
	if err != nil {
		return nil, nil, err
	}
	offset := utf8.RuneCountInString(prefix)
	kept := plan[:0]
	for _, sp := range plan {
		if sp.end <= offset {
			continue
		}
		sp.start = max(sp.start, offset) - offset
		sp.end -= offset
		kept = append(kept, sp)
	}
	return kept, runes[offset:], nil
}

// checkResidual fails with ErrResidual when a rule still matches text.
func (s *Sanitizer) checkResidual(ctx context.Context, text string) error {
	runes := []rune(text)
	if strings.Contains(text, placeholderPrefix) {
		maskPlaceholders(runes, s.placeholders)
	}
	found, err := findSpans(ctx, s.rules, runes)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return ErrResidual
	}
	return nil
}

// plan returns the replacement plan for runes (the runes of text). Matching
// runs with existing placeholders masked; the returned spans index runes.
func (s *Sanitizer) plan(ctx context.Context, text string, runes []rune) ([]span, error) {
	masked := s.masked(text, runes)
	found, err := findSpans(ctx, s.rules, masked)
	if err != nil {
		return nil, err
	}
	return resolveSpans(found, masked), nil
}

// masked returns runes with existing placeholders masked. Only text that
// contains the placeholder prefix is copied; other text is matched as is.
func (s *Sanitizer) masked(text string, runes []rune) []rune {
	if !strings.Contains(text, placeholderPrefix) {
		return runes
	}
	return maskPlaceholders(append([]rune(nil), runes...), s.placeholders)
}
