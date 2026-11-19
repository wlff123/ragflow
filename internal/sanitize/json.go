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
	key string
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

// sanitizeJSON replaces sensitive values inside a JSON document while keeping
// it valid JSON: only string and number tokens are rewritten, every other byte
// (keys order, whitespace, punctuation) is kept as is.
//
// A value is matched together with its key ("key: value"), so the key/value
// rule sees `"password": "..."` the same way it does in plain text. A
// replaced number becomes a JSON string holding the placeholder, so
// `"phone": 13800138000` turns into `"phone": "[敏感信息已移除：手机号]"`.
// text must satisfy isJSONDocument.
func (s *Sanitizer) sanitizeJSON(ctx context.Context, text string) (Result, error) {
	var (
		stack []jsonFrame
		out   Result
		b     strings.Builder
		pos   int // text[:pos] is already written to b
	)
	b.Grow(len(text))
	// write sanitizes one scalar token text[start:end] holding value. key is
	// the enclosing object key, or "" for keys themselves and array elements.
	write := func(start, end int, key, value string) error {
		var (
			r   Result
			err error
		)
		if key == "" {
			r, err = s.sanitizeText(ctx, value)
		} else {
			r, err = s.sanitizeKeyed(ctx, key, value)
		}
		if err != nil || r.Count == 0 {
			return err
		}
		raw, err := encodeJSONString(r.Text)
		if err != nil {
			return err
		}
		b.WriteString(text[pos:start])
		b.WriteString(raw)
		pos = end
		out.Add(r)
		return nil
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
			key := f.enclosingKey()
			if f != nil && f.object && f.expectKey {
				f.expectKey = false
				f.key = decoded
				key = ""
			}
			if err := write(i, end, key, decoded); err != nil {
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
