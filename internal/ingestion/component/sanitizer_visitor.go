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

package component

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"strings"

	"ragflow/internal/entity"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sanitize"
	"ragflow/internal/utility"
)

// maxSanitizeDepth bounds recursion into nested item maps.
const maxSanitizeDepth = 64

// nonTextKeys are item fields that never hold document body text: type
// discriminators, layout and position data, media payloads and references,
// and the sheet name (sheet names are out of scope). Every other string value
// of an item is treated as body text and sanitized, so a field a parser adds
// later is covered by default; a value of a type the walker cannot inspect
// fails the node instead of passing through unchecked.
var nonTextKeys = map[string]bool{
	parser.DocTypeKey: true,
	"layout":          true,
	"layout_type":     true,
	"layoutno":        true,
	"image":           true,
	"media_ref":       true,
	"img_id":          true,
	"positions":       true,
	"_pdf_positions":  true,
	"bbox":            true,
	"page_number":     true,
	"sheet":           true,
	"sheet_index":     true,
	"style":           true,
	"format":          true,
	"encoding":        true,
}

// itemWalker visits the body text of parser items and sanitizes it, keeping
// item types and structure. It never mutates its input: a map, slice or table
// is copied only when something inside it changes, and returned as is
// otherwise. total accumulates the counts.
type itemWalker struct {
	ctx   context.Context
	s     *sanitize.Sanitizer
	total sanitize.Result
}

// field sanitizes one string value held under key ("" for free text) and
// reports whether it changed.
func (w *itemWalker) field(key, s string) (string, bool, error) {
	r, err := w.s.SanitizeField(w.ctx, key, s)
	if err != nil {
		return "", false, err
	}
	w.total.Add(r)
	return r.Text, r.Count > 0, nil
}

// GeneralChunker copies file.outline titles into the first PDF chunk.
func (w *itemWalker) outline(out map[string]any) error {
	file, _ := out["file"].(map[string]any)
	typ, _ := out["file_type"].(string)
	if typ = strings.TrimSpace(typ); typ == "" {
		name, _ := out["name"].(string)
		if strings.TrimSpace(name) == "" {
			name, _ = file["name"].(string)
		}
		typ = utility.GetFileExtension(strings.TrimSpace(name))
	}
	if !strings.EqualFold(typ, "pdf") {
		return nil
	}
	var clean any
	var changed bool
	var err error
	switch rows := file["outline"].(type) {
	case nil:
		return nil
	case []map[string]any:
		clean, changed, err = cloneOnChange(rows, w.outlineTitle)
	case []any:
		clean, changed, err = cloneOnChange(rows, func(row any) (any, bool, error) {
			m, ok := row.(map[string]any)
			if !ok {
				return nil, false, errUnsupportedPayload
			}
			return w.outlineTitle(m)
		})
	default:
		return errUnsupportedPayload
	}
	if err == nil && changed {
		file = maps.Clone(file)
		file["outline"] = clean
		out["file"] = file
	}
	return err
}

func (w *itemWalker) outlineTitle(row map[string]any) (map[string]any, bool, error) {
	title, ok := row["title"].(string)
	if !ok {
		return row, false, nil
	}
	clean, changed, err := w.field("", title)
	if changed {
		row = maps.Clone(row)
		row["title"] = clean
	}
	return row, changed, err
}

func (w *itemWalker) items(items []parser.DocItem) ([]parser.DocItem, error) {
	out := make([]parser.DocItem, len(items))
	for i, it := range items {
		clean, err := w.item(it)
		if err != nil {
			return nil, err
		}
		out[i] = clean
	}
	return out, nil
}

func (w *itemWalker) item(it parser.DocItem) (parser.DocItem, error) {
	var err error
	switch t := it.(type) {
	case nil:
		return nil, nil
	case parser.TextItem:
		if t.Text, _, err = w.field("", t.Text); err != nil {
			return nil, err
		}
		t.Extra, _, err = w.stringMap(t.Extra, 0)
		return t, err
	case parser.TableItem:
		if t.Table, err = w.table(t.Table, t.Sheet != ""); err != nil {
			return nil, err
		}
		t.Extra, _, err = w.stringMap(t.Extra, 0)
		return t, err
	case parser.ImageItem:
		// Only the text (alt / OCR / vision description) is sanitized; image
		// bytes and media references are out of scope.
		if t.Text, _, err = w.field("", t.Text); err != nil {
			return nil, err
		}
		t.Extra, _, err = w.stringMap(t.Extra, 0)
		return t, err
	case parser.RawItem:
		t.M, _, err = w.stringMap(t.M, 0)
		return t, err
	default:
		// An item type added later: sanitize its wire map, which keeps the
		// item shape and type discriminator.
		m, _, err := w.stringMap(it.ToMap(), 0)
		if err != nil {
			return nil, err
		}
		return parser.DocItemFromMap(m), nil
	}
}

// table sanitizes every cell and the caption, keeping the grid shape: a cell
// holding only a sensitive value becomes a cell holding the placeholder. A
// spreadsheet table (one that belongs to a sheet) uses the sheet name as its
// caption; like the sheet field it is out of scope and kept as is.
func (w *itemWalker) table(t *entity.TableData, sheetCaption bool) (*entity.TableData, error) {
	if t == nil {
		return nil, nil
	}
	var (
		cp     *entity.TableData
		copied []bool
	)
	row := func(i int) []entity.TableCell {
		if cp == nil {
			c := *t
			c.Grid = append([][]entity.TableCell(nil), t.Grid...)
			cp, copied = &c, make([]bool, len(t.Grid))
		}
		if !copied[i] {
			cp.Grid[i] = append([]entity.TableCell(nil), t.Grid[i]...)
			copied[i] = true
		}
		return cp.Grid[i]
	}
	for i, cells := range t.Grid {
		for j, cell := range cells {
			if cell.Covered || cell.Text == "" {
				continue
			}
			clean, changed, err := w.field("", cell.Text)
			if err != nil {
				return nil, err
			}
			if changed {
				row(i)[j].Text = clean
			}
		}
	}
	if t.Caption != "" && !sheetCaption {
		clean, changed, err := w.field("", t.Caption)
		if err != nil {
			return nil, err
		}
		if changed {
			if cp == nil {
				c := *t
				cp = &c
			}
			cp.Caption = clean
		}
	}
	if cp == nil {
		return t, nil
	}
	return cp, nil
}

// stringMap sanitizes the body-text values of m, each with its key as
// context, and reports whether anything changed. Keys are kept; nonTextKeys
// and inert values are passed through. m itself is returned when nothing
// changed.
func (w *itemWalker) stringMap(m map[string]any, depth int) (map[string]any, bool, error) {
	var out map[string]any
	for k, v := range m {
		if nonTextKeys[k] {
			continue
		}
		clean, changed, err := w.value(k, v, depth+1)
		if err != nil {
			return nil, false, err
		}
		if changed {
			if out == nil {
				out = maps.Clone(m)
			}
			out[k] = clean
		}
	}
	if out == nil {
		return m, false, nil
	}
	return out, true, nil
}

// value sanitizes one field value held under key and reports whether it
// changed. Slice elements keep the key of the field holding the slice.
func (w *itemWalker) value(key string, v any, depth int) (any, bool, error) {
	if depth > maxSanitizeDepth {
		return nil, false, errUnsupportedPayload
	}
	switch t := v.(type) {
	case string:
		return w.field(key, t)
	case json.Number:
		clean, changed, err := w.field(key, string(t))
		if err != nil || !changed {
			return t, false, err
		}
		return clean, true, nil
	case []string:
		return cloneOnChange(t, func(s string) (string, bool, error) { return w.field(key, s) })
	case []any:
		return cloneOnChange(t, func(e any) (any, bool, error) { return w.value(key, e, depth+1) })
	case map[string]any:
		return w.stringMap(t, depth)
	case []map[string]any:
		return cloneOnChange(t, func(e map[string]any) (map[string]any, bool, error) { return w.stringMap(e, depth) })
	case *entity.TableData:
		out, err := w.table(t, false)
		return out, err == nil && out != t, err
	default:
		if inertValue(reflect.ValueOf(v)) {
			return v, false, nil
		}
		return nil, false, errUnsupportedPayload
	}
}

// cloneOnChange maps fn over in, copying in only once an element changes.
func cloneOnChange[T any](in []T, fn func(T) (T, bool, error)) ([]T, bool, error) {
	var out []T
	for i, e := range in {
		clean, changed, err := fn(e)
		if err != nil {
			return nil, false, err
		}
		if changed {
			if out == nil {
				out = append([]T(nil), in...)
			}
			out[i] = clean
		}
	}
	if out == nil {
		return in, false, nil
	}
	return out, true, nil
}

// inertValue reports whether v carries no text: nil, booleans, numbers, and
// pointers, slices and arrays of those. Numbers are left as they are: item
// numbers are positions, sizes and page indexes, never body text.
func inertValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Invalid, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	case reflect.Pointer, reflect.Interface:
		return v.IsNil() || inertValue(v.Elem())
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return false // byte data may hold text
		}
		for i := 0; i < v.Len(); i++ {
			if !inertValue(v.Index(i)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
