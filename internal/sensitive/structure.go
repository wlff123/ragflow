package sensitive

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CleanValue recursively checks business keys and values. Callers must project
// typed system fields out explicitly; arbitrary user keys are never exempted.
func (e *Engine) cleanBusinessValue(ctx context.Context, value any) (any, int64, error) {
	return e.cleanValue(ctx, value, "", e.deadline(ctx), 0)
}

func (e *Engine) cleanValue(ctx context.Context, value any, key string, deadline time.Time, depth int) (any, int64, error) {
	if depth > 100 {
		return nil, 0, Failure("SP_STRUCTURE_INVALID")
	}
	if err := checkBudget(ctx, deadline); err != nil {
		return nil, 0, err
	}
	switch v := value.(type) {
	case nil, bool:
		return value, 0, nil
	case string, json.Number:
		text := ""
		if s, ok := v.(string); ok {
			text = s
		} else {
			text = string(v.(json.Number))
		}
		// Keep the original semantic key for credential detection, even when the
		// display key itself needs replacement. JSON quoting is handled below.
		prefix := ""
		if key != "" {
			prefix = key + ": "
		}
		spans, err := e.matches(ctx, prefix+text, deadline)
		if err != nil {
			return nil, 0, err
		}
		prefixLen := len([]rune(prefix))
		for _, s := range spans {
			if s.rule.Scope == "value_after_separator" && s.start >= prefixLen {
				// Clean the contextual value first, then scan the complete value.
				r, err := e.clean(ctx, prefix+text, deadline)
				if err != nil {
					return nil, 0, err
				}
				if !strings.HasPrefix(r.Text, prefix) {
					return nil, 0, Failure("SP_STRUCTURE_INVALID")
				}
				return strings.TrimPrefix(r.Text, prefix), r.Count, nil
			}
		}
		r, err := e.clean(ctx, text, deadline)
		if err != nil {
			return nil, 0, err
		}
		if r.Count == 0 {
			return value, 0, nil
		}
		return r.Text, r.Count, nil
	case float64:
		return e.cleanNumber(ctx, v, strconv.FormatFloat(v, 'f', -1, 64), key, deadline, depth)
	case int:
		return e.cleanNumber(ctx, v, strconv.Itoa(v), key, deadline, depth)
	case int64:
		return e.cleanNumber(ctx, v, strconv.FormatInt(v, 10), key, deadline, depth)
	case []any:
		out := make([]any, len(v))
		var total int64
		for i, x := range v {
			clean, n, err := e.cleanValue(ctx, x, key, deadline, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[i] = clean
			total += n
		}
		return out, total, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		var total int64
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name, err := e.clean(ctx, k, deadline)
			if err != nil {
				return nil, 0, err
			}
			if _, exists := out[name.Text]; exists {
				return nil, 0, Failure("SP_STRUCTURE_INVALID")
			}
			clean, n, err := e.cleanValue(ctx, v[k], k, deadline, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out[name.Text] = clean
			total += n + name.Count
		}
		return out, total, nil
	default:
		// Parser extras often use typed slices or maps. Inspect their values
		// directly; binary buffers and arbitrary structs remain unsupported.
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Slice, reflect.Array:
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				return nil, 0, Failure("SP_STRUCTURE_INVALID")
			}
			normalized := make([]any, rv.Len())
			for i := range normalized {
				normalized[i] = rv.Index(i).Interface()
			}
			return e.cleanValue(ctx, normalized, key, deadline, depth+1)
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return nil, 0, Failure("SP_STRUCTURE_INVALID")
			}
			normalized := make(map[string]any, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				normalized[iter.Key().String()] = iter.Value().Interface()
			}
			return e.cleanValue(ctx, normalized, key, deadline, depth+1)
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32:
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, 0, Failure("SP_STRUCTURE_INVALID")
			}
			return e.cleanNumber(ctx, value, string(encoded), key, deadline, depth+1)
		}
		return nil, 0, Failure("SP_STRUCTURE_INVALID")
	}
}

// cleanNumber scans a number by its encoded text and keeps the original typed
// value when nothing was replaced.
func (e *Engine) cleanNumber(ctx context.Context, orig any, encoded, key string, deadline time.Time, depth int) (any, int64, error) {
	clean, n, err := e.cleanValue(ctx, json.Number(encoded), key, deadline, depth)
	if n == 0 && err == nil {
		return orig, 0, nil
	}
	return clean, n, err
}

// decodeJSON rejects duplicate object keys instead of silently losing values.
func decodeJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 100 {
		return nil, Failure("SP_STRUCTURE_INVALID")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		out := map[string]any{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := k.(string)
			if !ok {
				return nil, Failure("SP_STRUCTURE_INVALID")
			}
			if _, ok := out[key]; ok {
				return nil, Failure("SP_STRUCTURE_INVALID")
			}
			v, err := decodeJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, Failure("SP_STRUCTURE_INVALID")
		}
		return out, nil
	case json.Delim('['):
		out := []any{}
		for d.More() {
			v, err := decodeJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, Failure("SP_STRUCTURE_INVALID")
		}
		return out, nil
	default:
		if _, ok := t.(json.Delim); ok {
			return nil, Failure("SP_STRUCTURE_INVALID")
		}
		return t, nil
	}
}

func (e *Engine) cleanJSON(ctx context.Context, text string) (Result, error) {
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	v, err := decodeJSON(d, 0)
	if err != nil {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	if _, err = d.Token(); err != io.EOF {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	v, n, err := e.CleanValue(ctx, v)
	if err != nil {
		return Result{}, err
	}
	// Keep <, > and & literal: HTML escaping would rewrite business text.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	out := strings.TrimSuffix(b.String(), "\n")
	if err = e.Scan(ctx, out); err != nil {
		return Result{}, err
	}
	return Result{Text: out, Count: n, SourceCharacters: e.Characters(text), EffectiveCharacters: e.Characters(out)}, nil
}

// CleanYAML preserves scalar types unless replacing a value requires a string.
// Alias graphs and custom tags fail closed instead of escaping value inspection.
func (e *Engine) cleanYAML(ctx context.Context, text string) (Result, error) {
	var root yaml.Node
	d := yaml.NewDecoder(strings.NewReader(text))
	if d.Decode(&root) != nil {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	deadline := e.deadline(ctx)
	n, err := e.cleanYAMLNode(ctx, &root, "", deadline, 0)
	if err != nil {
		return Result{}, err
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if enc.Encode(&root) != nil || enc.Close() != nil {
		return Result{}, Failure("SP_STRUCTURE_INVALID")
	}
	if err = e.Scan(ctx, b.String()); err != nil {
		return Result{}, err
	}
	return Result{Text: b.String(), Count: n, SourceCharacters: e.Characters(text), EffectiveCharacters: e.Characters(b.String())}, nil
}

func (e *Engine) cleanYAMLNode(ctx context.Context, node *yaml.Node, key string, deadline time.Time, depth int) (int64, error) {
	if depth > 100 || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return 0, Failure("SP_STRUCTURE_INVALID")
	}
	if err := checkBudget(ctx, deadline); err != nil {
		return 0, err
	}
	var total int64
	// Comments are business text too; sanitize rather than retaining raw values.
	for _, comment := range []*string{&node.HeadComment, &node.LineComment, &node.FootComment} {
		if *comment == "" {
			continue
		}
		r, err := e.clean(ctx, *comment, deadline)
		if err != nil {
			return 0, err
		}
		*comment = r.Text
		total += r.Count
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			n, err := e.cleanYAMLNode(ctx, child, key, deadline, depth+1)
			if err != nil {
				return 0, err
			}
			total += n
		}
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			k := node.Content[i]
			if k.Kind != yaml.ScalarNode || i+1 >= len(node.Content) {
				return 0, Failure("SP_STRUCTURE_INVALID")
			}
			originalKey := k.Value
			n, err := e.cleanYAMLNode(ctx, k, "", deadline, depth+1)
			if err != nil {
				return 0, err
			}
			total += n
			if seen[k.Value] {
				return 0, Failure("SP_STRUCTURE_INVALID")
			}
			seen[k.Value] = true
			n, err = e.cleanYAMLNode(ctx, node.Content[i+1], originalKey, deadline, depth+1)
			if err != nil {
				return 0, err
			}
			total += n
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" && node.Tag != "!!int" && node.Tag != "!!float" && node.Tag != "!!bool" && node.Tag != "!!null" && node.Tag != "!!timestamp" {
			return 0, Failure("SP_STRUCTURE_INVALID")
		}
		v, n, err := e.cleanValue(ctx, node.Value, key, deadline, depth+1)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			node.Value = v.(string)
			node.Tag = "!!str"
			node.Style = yaml.DoubleQuotedStyle
		}
		total += n
	default:
		return 0, Failure("SP_STRUCTURE_INVALID")
	}
	return total, nil
}
