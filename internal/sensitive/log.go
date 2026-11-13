package sensitive

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
)

// CleanLogJSON is the logging adapter; it does not use a document Session or
// validate minimum document length. Engine failures contain no source payload.
func (e *Engine) CleanLogJSON(ctx context.Context, data []byte) ([]byte, error) {
	ctx = e.WithBudget(ctx)
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	value, err := decodeJSON(d, 0)
	if err != nil {
		return nil, Failure("SP_STRUCTURE_INVALID")
	}
	value, err = e.cleanLogJSONStrings(ctx, value, 0)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, Failure("SP_STRUCTURE_INVALID")
	}
	r, err := e.CleanJSON(ctx, string(encoded))
	if err != nil {
		return nil, err
	}
	return []byte(r.Text), nil
}

// Log strings may contain JSON bodies after an error prefix or SSE envelope.
// Decode objects/arrays before matching to retain escaped keys and field context.
func (e *Engine) cleanLogJSONStrings(ctx context.Context, value any, depth int) (any, error) {
	if depth > 100 {
		return nil, Failure("SP_STRUCTURE_INVALID")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			clean, err := e.cleanLogJSONStrings(ctx, child, depth+1)
			if err != nil {
				return nil, err
			}
			v[key] = clean
		}
	case []any:
		for i, child := range v {
			clean, err := e.cleanLogJSONStrings(ctx, child, depth+1)
			if err != nil {
				return nil, err
			}
			v[i] = clean
		}
	case string:
		var out strings.Builder
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			i := strings.IndexAny(v, "{[")
			if i < 0 {
				out.WriteString(v)
				return out.String(), nil
			}
			out.WriteString(v[:i])
			v = v[i:]
			d := json.NewDecoder(strings.NewReader(v))
			var raw json.RawMessage
			if d.Decode(&raw) != nil {
				// An ordinary bracket (e.g. a placeholder) is not JSON.
				out.WriteByte(v[0])
				v = v[1:]
				continue
			}
			consumed := int(d.InputOffset())
			d = json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			nested, err := decodeJSON(d, 0)
			if err != nil {
				return nil, Failure("SP_STRUCTURE_INVALID")
			}
			nested, err = e.cleanLogJSONStrings(ctx, nested, depth+1)
			if err != nil {
				return nil, err
			}
			clean, _, err := e.CleanValue(ctx, nested)
			if err != nil {
				return nil, err
			}
			b, err := json.Marshal(clean)
			if err != nil {
				return nil, Failure("SP_STRUCTURE_INVALID")
			}
			out.Write(b)
			v = v[consumed:]
		}
	}
	return value, nil
}
