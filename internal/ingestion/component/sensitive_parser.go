package component

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"reflect"
	"strings"

	"ragflow/internal/entity"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sensitive"
)

// cleanParserOutput runs before Globals can expose the parser's raw output.
func cleanParserOutput(ctx context.Context, out map[string]any) error {
	session := sensitive.FromContext(ctx)
	if session == nil {
		return nil
	}
	e := session.Processor.Engine
	items, ok := out["json"].([]parser.DocItem)
	if !ok {
		return sensitive.Failure("SP_STRUCTURE_INVALID")
	}
	cleaned := make([]parser.DocItem, 0, len(items))
	result := sensitive.Result{}
	ext := strings.ToLower(filepath.Ext(session.Name))
	structured := ext == ".json" || ext == ".jsonl" || ext == ".ldjson" || ext == ".yaml" || ext == ".yml"
	for i := 0; i < len(items); {
		m := items[i].ToMap()
		kind, _ := m["doc_type_kwd"].(string)
		if table, exists := m["table"]; exists {
			if _, ok := table.(*entity.TableData); !ok {
				return sensitive.Failure("SP_STRUCTURE_INVALID")
			}
		}
		if kind == parser.DocTypeText && !structured {
			var texts []string
			group := []map[string]any{m}
			for end := i + 1; end < len(items); end++ {
				current := items[end].ToMap()
				if current["doc_type_kwd"] != parser.DocTypeText {
					break
				}
				group = append(group, current)
			}
			for _, current := range group {
				text, ok := current["text"].(string)
				if !ok {
					return sensitive.Failure("SP_STRUCTURE_INVALID")
				}
				texts = append(texts, text)
			}
			parts, r, err := e.CleanSegments(ctx, texts)
			if err != nil {
				return err
			}
			result.Add(r)
			for j, current := range group {
				current["text"] = parts[j]
				if err := cleanParserBusinessFields(ctx, e, current); err != nil {
					return err
				}
				cleaned = append(cleaned, parser.DocItemFromMap(current))
			}
			i += len(group)
			continue
		}
		if table, ok := m["table"].(*entity.TableData); ok && table != nil {
			// Clone the typed table so no raw aliases escape through parser caches.
			b, err := json.Marshal(table)
			if err != nil {
				return sensitive.Failure("SP_STRUCTURE_INVALID")
			}
			var clone entity.TableData
			if json.Unmarshal(b, &clone) != nil {
				return sensitive.Failure("SP_STRUCTURE_INVALID")
			}
			for row := range clone.Grid {
				for col := range clone.Grid[row] {
					cell := &clone.Grid[row][col]
					r, err := e.Clean(ctx, cell.Text)
					if err != nil {
						return err
					}
					cell.Text = r.Text
					if !cell.Covered {
						result.Add(r)
					}
				}
			}
			r, err := e.Clean(ctx, clone.Caption)
			if err != nil {
				return err
			}
			clone.Caption = r.Text
			m["table"] = &clone
		} else if text, ok := m["text"].(string); ok {
			var r sensitive.Result
			var err error
			switch ext {
			case ".json", ".jsonl", ".ldjson":
				if session.JSONSourceResult == nil {
					return sensitive.Failure("SP_PRESPLIT_MISSING")
				}
				r, err = e.Clean(ctx, text)
			case ".yaml", ".yml":
				r, err = e.CleanYAML(ctx, text)
			default:
				r, err = e.Clean(ctx, text)
			}
			if err != nil {
				return err
			}
			m["text"] = r.Text
			result.Add(r)
		}
		if err := cleanParserBusinessFields(ctx, e, m); err != nil {
			return err
		}
		cleaned = append(cleaned, parser.DocItemFromMap(m))
		i++
	}
	if session.JSONSourceResult != nil {
		result = *session.JSONSourceResult
		result.Text = ""
	}
	if err := sensitive.ValidateContent(result.SourceCharacters, result.EffectiveCharacters, session.Processor.MinimumCharacters, session.Processor.MinimumRatio); err != nil {
		return err
	}
	if file, ok := out["file"].(map[string]any); ok {
		clean, _, err := e.CleanValue(ctx, file)
		if err != nil {
			return err
		}
		out["file"] = clean
	}
	out["json"] = cleaned
	out["name"] = session.Name
	session.Result = result
	session.Parsed = true
	return session.SealOutput(out)
}

func cleanParserBusinessFields(ctx context.Context, e *sensitive.Engine, m map[string]any) error {
	business := map[string]any{}
	for key, value := range m {
		switch key {
		case "text", "table", "doc_type_kwd":
			continue
		case "_source_json_value":
			delete(m, key)
			continue
		case "positions", "page_number", "page_num_int", "position_int", "level", "_pdf_positions", "sheet_index", "media_order":
			if !validParserCoordinates(reflect.ValueOf(value), 0) {
				return sensitive.Failure("SP_STRUCTURE_INVALID")
			}
			continue
		case "image", "media_ref", "img_id":
			delete(m, key)
			continue
		}
		business[key] = value
		delete(m, key)
	}
	clean, _, err := e.CleanValue(ctx, business)
	if err != nil {
		return err
	}
	for key, value := range clean.(map[string]any) {
		if _, exists := m[key]; exists {
			return sensitive.Failure("SP_STRUCTURE_INVALID")
		}
		m[key] = value
	}
	return nil
}

func validParserCoordinates(v reflect.Value, depth int) bool {
	if depth > 6 || !v.IsValid() {
		return false
	}
	if v.Kind() == reflect.Interface {
		return validParserCoordinates(v.Elem(), depth+1)
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !validParserCoordinates(v.Index(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() >= -1000000 && v.Int() <= 1000000
	case reflect.Float32, reflect.Float64:
		return !math.IsNaN(v.Float()) && !math.IsInf(v.Float(), 0) && v.Float() >= -1000000 && v.Float() <= 1000000
	default:
		return false
	}
}
