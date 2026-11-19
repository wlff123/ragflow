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

// Sanitizer ingestion component: removes sensitive values from the parsed
// document before it is chunked, embedded and indexed.
//
// It sits between Parser and the chunker:
//
//	File -> Parser -> Sanitizer -> Chunker -> [Extractor] -> Tokenizer
//
// The node only adapts the pipeline payload to the sanitize library: it walks
// the Parser envelope, sanitizes every body text through sanitize.Sanitizer
// and returns an envelope of the same shape plus a sanitize_report. All
// business rules (rule set, placeholder, merging, re-check, counting) live in
// internal/sanitize. The node has no parameters, reads no database and
// touches no storage. Fields of the envelope other than the body payload
// (name, file_type, file, doc_id, bucket, path, lang, ...) pass through
// unchanged.

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"go.uber.org/zap"
	"gorm.io/gorm"

	"ragflow/internal/agent/runtime"
	"ragflow/internal/common"
	"ragflow/internal/entity"
	"ragflow/internal/ingestion/component/schema"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sanitize"
)

// ComponentNameSanitizer is the DSL component_name of the Sanitizer node.
const ComponentNameSanitizer = schema.ComponentNameSanitizer

// errUnsupportedPayload reports an upstream envelope the node cannot
// sanitize: an unknown output_format or a payload or field value of an
// unexpected type. Like the library errors its text is a stable code.
var errUnsupportedPayload = errors.New("SANITIZE_UNSUPPORTED_PAYLOAD")

// SanitizerComponent is the Sanitizer ingestion node.
type SanitizerComponent struct {
	load func() (*sanitize.Sanitizer, error)
}

// NewSanitizerComponent builds the node with the process-wide sanitizer.
// params is accepted for the factory contract and ignored: the node has no
// parameters, because the rules (chapter 7 of the requirement) and the
// placeholder template are fixed.
func NewSanitizerComponent(_ map[string]any) (runtime.Component, error) {
	return &SanitizerComponent{load: sanitize.Default}, nil
}

// Inputs returns the input metadata: the Parser output envelope.
func (c *SanitizerComponent) Inputs() map[string]string {
	return map[string]string{
		"output_format": "Upstream payload discriminator: json / markdown / text / html.",
		"json":          "Parsed document items when output_format == \"json\".",
		"markdown":      "Markdown payload when output_format == \"markdown\".",
		"text":          "Plain-text payload when output_format == \"text\".",
		"html":          "HTML payload when output_format == \"html\".",
		"name":          "Document name (passed through, not sanitized).",
	}
}

// Outputs returns the output metadata: the input envelope with body text
// sanitized, plus the report.
func (c *SanitizerComponent) Outputs() map[string]string {
	return map[string]string{
		"output_format":          "Same as the input.",
		"json":                   "Sanitized document items (same item types and structure as the input).",
		"markdown":               "Sanitized markdown payload.",
		"text":                   "Sanitized plain-text payload.",
		"html":                   "Sanitized HTML payload.",
		schema.KeySanitizeReport: "Replacement count, per-rule hits and the rule set version; no source text.",
	}
}

// Invoke sanitizes the upstream envelope. Any failure is returned as an error
// so the pipeline fails and no unsanitized content reaches the chunker.
func (c *SanitizerComponent) Invoke(ctx context.Context, _ *gorm.DB, inputs map[string]any) (map[string]any, error) {
	s, err := c.load()
	if err != nil {
		return nil, fmt.Errorf("sanitizer: %w", err)
	}

	out := maps.Clone(inputs)
	if out == nil {
		out = map[string]any{}
	}
	w := &itemWalker{ctx: ctx, s: s}

	format, _ := inputs["output_format"].(string)
	switch format {
	case "", "json":
		// An unset output_format means json, as for the chunker and tokenizer.
		payload, ok := inputs[schema.KeyParseItems]
		if !ok {
			break
		}
		items, err := docItemsFromPayload(payload)
		if err != nil {
			return nil, fmt.Errorf("sanitizer: %w", err)
		}
		sanitized, err := w.items(items)
		if err != nil {
			return nil, fmt.Errorf("sanitizer: %w", err)
		}
		out[schema.KeyParseItems] = sanitized
	case "markdown", "text", "html":
		text, ok := stringPayload(inputs[format])
		if !ok {
			return nil, fmt.Errorf("sanitizer: %w", errUnsupportedPayload)
		}
		if text == nil {
			break // absent payload: nothing to sanitize, nothing to add
		}
		clean, changed, err := w.field("", *text)
		if err != nil {
			return nil, fmt.Errorf("sanitizer: %w", err)
		}
		if changed {
			out[format] = clean
		}
	default:
		return nil, fmt.Errorf("sanitizer: %w", errUnsupportedPayload)
	}

	info := s.Rules()
	report := schema.SanitizeReport{
		ReplacementCount: w.total.Count,
		RuleHits:         w.total.RuleHits,
		RulesVersion:     info.Version,
		RulesSource:      info.Source,
	}
	if report.RuleHits == nil {
		report.RuleHits = map[string]int{}
	}
	out[schema.KeySanitizeReport] = report

	common.Debug("sanitizer stage",
		zap.String("component", ComponentNameSanitizer),
		zap.String("output_format", format),
		zap.Int("replacement_count", report.ReplacementCount),
		zap.Any("rule_hits", report.RuleHits),
	)
	return out, nil
}

// docItemsFromPayload accepts the Parser's typed []parser.DocItem as well as
// the map forms the payload takes after a JSON round trip.
func docItemsFromPayload(v any) ([]parser.DocItem, error) {
	switch t := v.(type) {
	case nil:
		return []parser.DocItem{}, nil
	case []parser.DocItem:
		return t, nil
	case []map[string]any:
		items := make([]parser.DocItem, 0, len(t))
		for _, m := range t {
			it, err := docItemFromMap(m)
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
		return items, nil
	case []any:
		items := make([]parser.DocItem, 0, len(t))
		for _, e := range t {
			switch it := e.(type) {
			case parser.DocItem:
				items = append(items, it)
			case map[string]any:
				item, err := docItemFromMap(it)
				if err != nil {
					return nil, err
				}
				items = append(items, item)
			default:
				return nil, errUnsupportedPayload
			}
		}
		return items, nil
	default:
		return nil, errUnsupportedPayload
	}
}

// docItemFromMap builds the typed item for a wire map. A table whose "table"
// arrived as a JSON-decoded map is decoded into entity.TableData first, so it
// becomes a TableItem (walked with the table rules) instead of a RawItem.
func docItemFromMap(m map[string]any) (parser.DocItem, error) {
	if m[parser.DocTypeKey] == parser.DocTypeTable {
		if raw, ok := m["table"].(map[string]any); ok {
			b, err := json.Marshal(raw)
			if err != nil {
				return nil, errUnsupportedPayload
			}
			var td entity.TableData
			if err := json.Unmarshal(b, &td); err != nil {
				return nil, errUnsupportedPayload
			}
			m = maps.Clone(m)
			m["table"] = &td
		}
	}
	return parser.DocItemFromMap(m), nil
}

// stringPayload reads a markdown/text/html payload, which may be a string or
// a *string. It returns nil for an absent payload and false for a value of
// another type.
func stringPayload(v any) (*string, bool) {
	switch t := v.(type) {
	case string:
		return &t, true
	case *string:
		return t, true
	case nil:
		return nil, true
	default:
		return nil, false
	}
}

func init() {
	c := &SanitizerComponent{}
	runtime.MustRegister(ComponentNameSanitizer, runtime.CategoryIngestion,
		func(_ string, params map[string]any) (runtime.Component, error) {
			return NewSanitizerComponent(params)
		},
		runtime.Metadata{
			Version: "1.0.0",
			Inputs:  c.Inputs(),
			Outputs: c.Outputs(),
		})
}
