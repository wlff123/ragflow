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
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

// isJSONDocument reports whether text is a complete JSON object or array.
// Scalars are left to the plain-text path.
func isJSONDocument(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" || (t[0] != '{' && t[0] != '[') {
		return false
	}
	return json.Valid([]byte(t))
}

// jsonFrame is one open object or array while walking a JSON document.
type jsonFrame struct {
	object    bool
	expectKey bool
	// key is the last key read in an object, or for an array the key its
	// elements belong to ("" for a top-level array).
	key  string
	keys []int // key token indices in edits
}

type jsonEdit struct {
	start, end            int
	original, replacement string
	numberAt              int
}

// Reserve unchanged names before assigning names to rewritten keys.
func (s *Sanitizer) finishKeys(ctx context.Context, edits []jsonEdit, keys []int, out *Result) error {
	if len(keys) == 0 {
		return nil
	}
	used := make(map[string]bool, len(keys))
	for _, i := range keys {
		e := &edits[i]
		runes := []rune(e.original)
		plan, err := s.plan(ctx, e.original, runes, len(keys))
		if err != nil {
			return err
		}
		if len(plan) == 0 {
			used[e.original] = true
			continue
		}
		var hits map[string]int
		e.replacement, hits = render(runes, plan)
		first := plan[0]
		e.numberAt = len(string(runes[:first.start])) + len(placeholder(first.rule.Name)) - 1
		out.Add(Result{Count: len(plan), RuleHits: hits})
	}
	assigned := map[string]string{}
	next := map[string]int{}
	for _, i := range keys {
		e := &edits[i]
		if e.replacement == "" {
			continue
		}
		if name, ok := assigned[e.original]; ok {
			e.replacement = name
			continue
		}
		base := e.replacement
		for used[e.replacement] {
			n := max(2, next[base])
			next[base] = n + 1
			e.replacement = base[:e.numberAt] + "_" + strconv.Itoa(n) + base[e.numberAt:]
		}
		used[e.replacement] = true
		assigned[e.original] = e.replacement
	}
	return nil
}

// enclosingKey returns the key a value belongs to: array elements keep the
// key of the field holding the array, as in the ingestion item walker. It is
// "" at the top level.
func (f *jsonFrame) enclosingKey() string {
	if f == nil {
		return ""
	}
	return f.key
}

// sanitizeJSON matches decoded keys and values in a valid JSON document.
// It rewrites only matching tokens, preserving every other byte.
func (s *Sanitizer) sanitizeJSON(ctx context.Context, text string) (Result, error) {
	var stack []jsonFrame
	var edits []jsonEdit
	var out Result
	write := func(start, end int, key, value string) error {
		var r Result
		var err error
		if key == "" {
			r, err = s.sanitizeText(ctx, value)
		} else {
			r, err = s.sanitizeKeyed(ctx, key, value)
		}
		if err == nil && r.Count > 0 {
			edits = append(edits, jsonEdit{start: start, end: end, replacement: r.Text})
			out.Add(r)
		}
		return err
	}

	for i := 0; i < len(text); {
		var f *jsonFrame
		if n := len(stack); n > 0 {
			f = &stack[n-1]
		}
		switch c := text[i]; {
		case c == '{':
			stack = append(stack, jsonFrame{object: true, expectKey: true})
			i++
		case c == '[':
			stack = append(stack, jsonFrame{key: f.enclosingKey()})
			i++
		case c == '}' || c == ']':
			if err := s.finishKeys(ctx, edits, f.keys, &out); err != nil {
				return Result{}, err
			}
			stack = stack[:len(stack)-1]
			i++
		case c == ',':
			if f != nil && f.object {
				f.expectKey = true
			}
			i++
		case c == '"':
			end := scanJSONString(text, i)
			decoded, err := decodeJSONString(text[i:end])
			if err != nil {
				return Result{}, err
			}
			if f != nil && f.object && f.expectKey {
				f.expectKey = false
				f.key = decoded
				f.keys = append(f.keys, len(edits))
				edits = append(edits, jsonEdit{start: i, end: end, original: decoded})
			} else if err := write(i, end, f.enclosingKey(), decoded); err != nil {
				return Result{}, err
			}
			i = end
		case c == '-' || (c >= '0' && c <= '9'):
			end := i + 1
			for end < len(text) && strings.IndexByte("0123456789+-.eE", text[end]) >= 0 {
				end++
			}
			if err := write(i, end, f.enclosingKey(), text[i:end]); err != nil {
				return Result{}, err
			}
			i = end
		default:
			// ':', whitespace and the literals true/false/null
			i++
		}
	}
	if out.Count == 0 {
		return Result{Text: text}, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, e := range edits {
		if e.replacement == "" {
			continue
		}
		raw, err := encodeJSONString(e.replacement)
		if err != nil {
			return Result{}, err
		}
		b.WriteString(text[pos:e.start])
		b.WriteString(raw)
		pos = e.end
	}
	b.WriteString(text[pos:])
	out.Text = b.String()
	return out, nil
}

// decodeJSONString decodes a complete JSON string token. A token without
// escapes is its own content and is sliced instead of unmarshalled.
func decodeJSONString(token string) (string, error) {
	inner := token[1 : len(token)-1]
	if strings.IndexByte(inner, '\\') < 0 {
		return inner, nil
	}
	var decoded string
	err := json.Unmarshal([]byte(token), &decoded)
	return decoded, err
}

// scanJSONString returns the index just past the closing quote of the JSON
// string starting at text[start] == '"'. text is known to be valid JSON.
func scanJSONString(text string, start int) int {
	for i := start + 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(text)
}

// encodeJSONString encodes s as a JSON string without HTML escaping, so
// <, > and & stay literal like in the parser's own JSON output.
func encodeJSONString(s string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
