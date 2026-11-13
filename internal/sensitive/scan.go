package sensitive

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"reflect"
	"regexp"
)

// ScanValue checks decoded business keys and values without accepting a repaired
// result. Typed callers are normalized through JSON so nested aliases, numeric
// values and escaped strings receive the same semantic inspection.
func (e *Engine) ScanValue(ctx context.Context, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return Failure("SP_STRUCTURE_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var normalized any
	if decoder.Decode(&normalized) != nil {
		return Failure("SP_STRUCTURE_INVALID")
	}
	_, count, err := e.CleanValue(ctx, normalized)
	if err != nil {
		return err
	}
	if count != 0 {
		return Failure("SP_RESCAN_HIT")
	}
	return nil
}

var vectorField = regexp.MustCompile(`^q_[0-9]+_vec$`)

// ScanChunks checks all business fields, including unknown extension fields.
// Only the index's explicitly typed system fields are projected out; nested
// user metadata with identical names is still checked as business content.
func (e *Engine) ScanChunks(ctx context.Context, chunks []map[string]any) error {
	for _, chunk := range chunks {
		business := make(map[string]any, len(chunk))
		for key, value := range chunk {
			switch key {
			case "image", "media_ref", "img_id":
				if value != nil && value != "" {
					return Failure("SP_RESCAN_HIT")
				}
				continue
			case "id", "doc_id", "kb_id", "parent_id", "mom_id":
				if text, ok := value.(string); ok && validSystemID(text) {
					continue
				}
			case "create_timestamp_flt", "available_int", "chunk_order_int", "page_num_int", "position_int", "top_int", "positions", "_pdf_positions", "page_number", "sheet_index", "tk_nums", "pagerank_fea":
				if numericSystemValue(reflect.ValueOf(value), 0) {
					continue
				}
			}
			if vectorField.MatchString(key) && numericSystemValue(reflect.ValueOf(value), 0) {
				continue
			}
			business[key] = value
		}
		if err := e.ScanValue(ctx, business); err != nil {
			return err
		}
	}
	return nil
}

// validSystemID accepts server-generated hex IDs: 16 (xxhash chunk/parent IDs),
// 32 (UUID) or 64 (SHA-256) characters.
func validSystemID(text string) bool {
	if len(text) != 16 && len(text) != 32 && len(text) != 64 {
		return false
	}
	for _, r := range text {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func numericSystemValue(v reflect.Value, depth int) bool {
	if !v.IsValid() || depth > 6 {
		return false
	}
	if v.Kind() == reflect.Interface {
		return numericSystemValue(v.Elem(), depth+1)
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !numericSystemValue(v.Index(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	case reflect.Float32, reflect.Float64:
		return !math.IsNaN(v.Float()) && !math.IsInf(v.Float(), 0)
	default:
		return false
	}
}
