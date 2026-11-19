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
	"errors"
	"reflect"
	"strings"
	"testing"

	"ragflow/internal/agent/runtime"
	"ragflow/internal/entity"
	"ragflow/internal/ingestion/component/schema"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sanitize"
)

// All sample values are synthetic.
const (
	testPhone    = "13800138000"
	testPassword = "abcd1234efgh"
	phoneMark    = "[敏感信息已移除：手机号]"
	secretMark   = "[敏感信息已移除：密钥类]"
)

func newTestSanitizerNode(t *testing.T) runtime.Component {
	t.Helper()
	node, err := NewSanitizerComponent(nil)
	if err != nil {
		t.Fatalf("NewSanitizerComponent: %v", err)
	}
	return node
}

func invokeSanitizer(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	out, err := newTestSanitizerNode(t).Invoke(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	return out
}

func parserEnvelope(items []parser.DocItem) map[string]any {
	return map[string]any{
		"name":          "合同-" + "张三.txt",
		"file_type":     "txt",
		"doc_id":        "doc-1",
		"bucket":        "kb-1",
		"path":          "p/doc.txt",
		"lang":          "Chinese",
		"file":          map[string]any{"name": "doc.txt", "size": 10},
		"output_format": "json",
		"json":          items,
	}
}

func TestSanitizer_Registered(t *testing.T) {
	_, cat, meta, ok := runtime.DefaultRegistry.Lookup(ComponentNameSanitizer)
	if !ok || cat != runtime.CategoryIngestion || meta.Version != "1.0.0" {
		t.Fatalf("lookup Sanitizer: ok=%v cat=%v meta=%+v", ok, cat, meta)
	}
}

func TestSanitizer_JSONItems(t *testing.T) {
	positions := parser.Positions{}
	text := parser.TextItem{
		Text:  "联系电话 " + testPhone + "，password=" + testPassword,
		Extra: map[string]any{"layout": "text", "page_number": 3, "title": "联系人 " + testPhone},
	}
	table := parser.TableItem{
		Table: &entity.TableData{
			HeaderRows: 1,
			Caption:    "名单 " + testPhone,
			Grid: [][]entity.TableCell{
				{{Text: "姓名"}, {Text: "电话"}},
				{{Text: "张三"}, {Text: testPhone}},
				{{Text: "李四", ColSpan: 2}, {Covered: true}},
			},
		},
		Positions: positions,
	}
	image := parser.ImageItem{Text: "截图中的号码 " + testPhone, Image: "data:image/png;base64,AAAA"}
	raw := parser.RawItem{M: map[string]any{
		parser.DocTypeKey: "text",
		"from":            "a@example.com",
		"body":            "回电 " + testPhone,
		"attachments":     []any{"清单 " + testPhone + ".txt"},
	}}
	in := parserEnvelope([]parser.DocItem{text, table, image, raw})

	out := invokeSanitizer(t, in)

	items, ok := out["json"].([]parser.DocItem)
	if !ok || len(items) != 4 {
		t.Fatalf("json = %T len %d", out["json"], len(items))
	}

	gotText := items[0].(parser.TextItem)
	if gotText.Text != "联系电话 "+phoneMark+"，password="+secretMark {
		t.Fatalf("text = %q", gotText.Text)
	}
	if gotText.Extra["title"] != "联系人 "+phoneMark || gotText.Extra["layout"] != "text" || gotText.Extra["page_number"] != 3 {
		t.Fatalf("text extra = %v", gotText.Extra)
	}

	gotTable := items[1].(parser.TableItem)
	grid := gotTable.Table.Grid
	if len(grid) != 3 || len(grid[1]) != 2 || grid[1][1].Text != phoneMark || grid[1][0].Text != "张三" ||
		grid[2][0].ColSpan != 2 || !grid[2][1].Covered || gotTable.Table.HeaderRows != 1 {
		t.Fatalf("table grid = %+v", grid)
	}
	if gotTable.Table.Caption != "名单 "+phoneMark {
		t.Fatalf("table caption = %q", gotTable.Table.Caption)
	}

	gotImage := items[2].(parser.ImageItem)
	if gotImage.Text != "截图中的号码 "+phoneMark || gotImage.Image != image.Image {
		t.Fatalf("image = %+v", gotImage)
	}

	gotRaw := items[3].(parser.RawItem)
	if gotRaw.M["body"] != "回电 "+phoneMark || gotRaw.M["from"] != "a@example.com" ||
		gotRaw.M["attachments"].([]any)[0] != "清单 "+phoneMark+".txt" {
		t.Fatalf("raw = %v", gotRaw.M)
	}

	// Input is not mutated.
	if table.Table.Grid[1][1].Text != testPhone || text.Extra["title"] != "联系人 "+testPhone || raw.M["body"] != "回电 "+testPhone {
		t.Fatal("input items were mutated")
	}

	// Metadata passes through unchanged (the document name is out of scope).
	for _, k := range []string{"name", "file_type", "doc_id", "bucket", "path", "lang", "file", "output_format"} {
		if !reflect.DeepEqual(out[k], in[k]) {
			t.Fatalf("%s = %v, want %v", k, out[k], in[k])
		}
	}

	report, ok := out[schema.KeySanitizeReport].(schema.SanitizeReport)
	if !ok {
		t.Fatalf("report = %T", out[schema.KeySanitizeReport])
	}
	// text: phone + secret, title, caption, cell, image, body, attachment
	if report.ReplacementCount != 8 || report.RuleHits["CN_MOBILE"] != 7 || report.RuleHits["SECRET_KV"] != 1 ||
		report.RulesSource != sanitize.SourceBuiltin || report.RulesVersion == "" {
		t.Fatalf("report = %+v", report)
	}

	// The output still satisfies the chunker's upstream contract.
	docs, ok, err := schema.ChunkDocsFromDocItem(items)
	if err != nil || !ok || len(docs) != 4 {
		t.Fatalf("ChunkDocsFromDocItem: ok=%v err=%v len=%d", ok, err, len(docs))
	}
	for _, d := range docs {
		if strings.Contains(d.Text, testPhone) || strings.Contains(d.Text, testPassword) {
			t.Fatalf("raw value reached chunker input: %q", d.Text)
		}
	}
}

func TestSanitizer_MapItemsAndNoHits(t *testing.T) {
	in := map[string]any{
		"name":          "a.txt",
		"output_format": "json",
		"json": []map[string]any{
			{"text": "普通内容", parser.DocTypeKey: parser.DocTypeText},
			{"text": "电话 " + testPhone, parser.DocTypeKey: parser.DocTypeText},
		},
	}
	out := invokeSanitizer(t, in)
	items := out["json"].([]parser.DocItem)
	if items[0].(parser.TextItem).Text != "普通内容" || items[1].(parser.TextItem).Text != "电话 "+phoneMark {
		t.Fatalf("items = %v", items)
	}

	clean := map[string]any{"name": "a.txt", "output_format": "json", "json": []parser.DocItem{parser.TextItem{Text: "普通内容"}}}
	out = invokeSanitizer(t, clean)
	report := out[schema.KeySanitizeReport].(schema.SanitizeReport)
	if report.ReplacementCount != 0 || report.RuleHits == nil || len(report.RuleHits) != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestSanitizer_StringFormats(t *testing.T) {
	md := "# 联系方式\n\n| 姓名 | 电话 |\n|---|---|\n| 张三 | " + testPhone + " |\n"
	for _, format := range []string{"markdown", "text", "html"} {
		in := map[string]any{"name": "a", "output_format": format, format: md}
		out := invokeSanitizer(t, in)
		got, _ := out[format].(string)
		if strings.Contains(got, testPhone) || !strings.Contains(got, "| 张三 | "+phoneMark+" |") {
			t.Fatalf("%s = %q", format, got)
		}
	}
	// *string payloads are accepted too.
	s := "电话 " + testPhone
	out, err := newTestSanitizerNode(t).Invoke(context.Background(), nil, map[string]any{"output_format": "text", "text": &s})
	if err != nil || out["text"] != "电话 "+phoneMark {
		t.Fatalf("*string: %v %v", out["text"], err)
	}
	// An absent or unchanged payload is passed through as it is.
	out, err = newTestSanitizerNode(t).Invoke(context.Background(), nil, map[string]any{"output_format": "markdown"})
	if _, ok := out["markdown"]; err != nil || ok {
		t.Fatalf("absent payload: %v %v", out, err)
	}
	plain := "普通内容"
	out, err = newTestSanitizerNode(t).Invoke(context.Background(), nil, map[string]any{"output_format": "text", "text": &plain})
	if p, ok := out["text"].(*string); err != nil || !ok || p != &plain {
		t.Fatalf("unchanged payload: %#v %v", out["text"], err)
	}
}

func TestSanitizer_Errors(t *testing.T) {
	node := newTestSanitizerNode(t)
	ctx := context.Background()
	for name, in := range map[string]map[string]any{
		"chunks format": {"output_format": "chunks", "chunks": []any{}},
		"bad json type": {"output_format": "json", "json": "电话 " + testPhone},
		"bad text type": {"output_format": "text", "text": 42},
	} {
		_, err := node.Invoke(ctx, nil, in)
		if !errors.Is(err, errUnsupportedPayload) {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), testPhone) {
			t.Errorf("%s: error leaks source text: %v", name, err)
		}
	}

	failing := &SanitizerComponent{load: func() (*sanitize.Sanitizer, error) { return nil, sanitize.ErrRulesUnavailable }}
	if _, err := failing.Invoke(ctx, nil, parserEnvelope(nil)); !errors.Is(err, sanitize.ErrRulesUnavailable) {
		t.Fatalf("rules unavailable: err = %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	in := parserEnvelope([]parser.DocItem{parser.TextItem{Text: "电话 " + testPhone}})
	if _, err := node.Invoke(cancelled, nil, in); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: err = %v", err)
	}
}

func TestSanitizer_Idempotent(t *testing.T) {
	node := newTestSanitizerNode(t)
	in := parserEnvelope([]parser.DocItem{parser.TextItem{Text: "电话 " + testPhone}})
	first, err := node.Invoke(context.Background(), nil, in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := node.Invoke(context.Background(), nil, first)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first["json"], second["json"]) ||
		second[schema.KeySanitizeReport].(schema.SanitizeReport).ReplacementCount != 0 {
		t.Fatalf("second run changed output: %v", second["json"])
	}
}

func TestSanitizer_UnsetFormatMeansJSON(t *testing.T) {
	in := map[string]any{"name": "a", "json": []parser.DocItem{parser.TextItem{Text: "电话 " + testPhone}}}
	out := invokeSanitizer(t, in)
	if got := out["json"].([]parser.DocItem)[0].(parser.TextItem).Text; got != "电话 "+phoneMark {
		t.Fatalf("text = %q", got)
	}
	if _, ok := out["output_format"]; ok {
		t.Fatal("output_format must not be added")
	}

	// No payload at all: nothing to sanitize and no json key is invented.
	out = invokeSanitizer(t, map[string]any{"name": "a"})
	if _, ok := out["json"]; ok {
		t.Fatal("json key must not be added")
	}
}

func TestSanitizer_SheetNameCaptionKept(t *testing.T) {
	sheet := "名单" + testPhone
	sheetTable := parser.TableItem{Sheet: sheet, Table: &entity.TableData{
		Caption: sheet,
		Grid:    [][]entity.TableCell{{{Text: "电话"}}, {{Text: testPhone}}},
	}}
	pdfTable := parser.TableItem{Table: &entity.TableData{
		Caption: "表1 联系人 " + testPhone,
		Grid:    [][]entity.TableCell{{{Text: "x"}}},
	}}
	out := invokeSanitizer(t, parserEnvelope([]parser.DocItem{sheetTable, pdfTable}))
	items := out["json"].([]parser.DocItem)
	gotSheet := items[0].(parser.TableItem)
	if gotSheet.Sheet != sheet || gotSheet.Table.Caption != sheet || gotSheet.Table.Grid[1][0].Text != phoneMark {
		t.Fatalf("sheet table = %+v caption %q", gotSheet.Table.Grid, gotSheet.Table.Caption)
	}
	if got := items[1].(parser.TableItem).Table.Caption; got != "表1 联系人 "+phoneMark {
		t.Fatalf("pdf caption = %q", got)
	}
}

func TestSanitizer_FieldValueTypes(t *testing.T) {
	node := newTestSanitizerNode(t)
	inert := parser.TextItem{Text: "正文", Extra: map[string]any{
		"page_num_int": []int{1, 2},
		"top_int":      []float64{1.5},
		"ratio":        float32(0.5),
		"flag":         true,
		"nothing":      nil,
		"count":        json.Number("13800138000"),
	}}
	out, err := node.Invoke(context.Background(), nil, parserEnvelope([]parser.DocItem{inert}))
	if err != nil {
		t.Fatalf("inert values: %v", err)
	}
	extra := out["json"].([]parser.DocItem)[0].(parser.TextItem).Extra
	if extra["count"] != phoneMark || !reflect.DeepEqual(extra["page_num_int"], []int{1, 2}) || extra["flag"] != true {
		t.Fatalf("extra = %v", extra)
	}

	// A value the walker cannot inspect fails the node instead of passing
	// unchecked text through.
	for name, v := range map[string]any{
		"map[string]string":   map[string]string{"note": "电话 " + testPhone},
		"[]map[string]string": []map[string]string{{"note": "电话 " + testPhone}},
		"struct":              struct{ Note string }{"电话 " + testPhone},
		"[]byte":              []byte("电话 " + testPhone),
		"TableData value":     entity.TableData{Caption: testPhone},
	} {
		item := parser.TextItem{Text: "正文", Extra: map[string]any{"x": v}}
		_, err := node.Invoke(context.Background(), nil, parserEnvelope([]parser.DocItem{item}))
		if !errors.Is(err, errUnsupportedPayload) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSanitizer_FieldKeyContext(t *testing.T) {
	// The key of a structured field gives the key/value rule its context,
	// exactly as for a JSON document.
	raw := parser.RawItem{M: map[string]any{parser.DocTypeKey: "text", "password": testPassword, "note": testPassword}}
	text := parser.TextItem{Text: "正文", Extra: map[string]any{"api_key": testPassword}}
	out := invokeSanitizer(t, parserEnvelope([]parser.DocItem{raw, text}))
	items := out["json"].([]parser.DocItem)
	m := items[0].(parser.RawItem).M
	if m["password"] != secretMark || m["note"] != testPassword {
		t.Fatalf("raw = %v", m)
	}
	if got := items[1].(parser.TextItem).Extra["api_key"]; got != secretMark {
		t.Fatalf("extra api_key = %v", got)
	}
}

func TestSanitizer_NestingLimit(t *testing.T) {
	node := newTestSanitizerNode(t)
	var value any = testPhone
	for depth := 1; depth < maxSanitizeDepth; depth++ {
		value = []any{value}
	}
	invoke := func(v any) (map[string]any, error) {
		item := parser.TextItem{Extra: map[string]any{"nested": v}}
		return node.Invoke(t.Context(), nil, parserEnvelope([]parser.DocItem{item}))
	}
	out, err := invoke(value)
	if err != nil {
		t.Fatal(err)
	}
	if report := out[schema.KeySanitizeReport].(schema.SanitizeReport); report.RuleHits["CN_MOBILE"] != 1 {
		t.Fatalf("at depth limit: %+v", report)
	}
	if out, err := invoke([]any{value}); !errors.Is(err, errUnsupportedPayload) || out != nil {
		t.Fatalf("beyond depth limit: output present=%t err=%v", out != nil, err)
	}
}

func TestSanitizer_UnchangedValuesAreNotCopied(t *testing.T) {
	extra := map[string]any{"title": "普通标题", "page_num_int": []int{1}}
	table := &entity.TableData{Caption: "表1", Grid: [][]entity.TableCell{{{Text: "普通"}}}}
	in := parserEnvelope([]parser.DocItem{parser.TextItem{Text: "正文", Extra: extra}, parser.TableItem{Table: table}})
	out := invokeSanitizer(t, in)
	items := out["json"].([]parser.DocItem)
	if reflect.ValueOf(items[0].(parser.TextItem).Extra).Pointer() != reflect.ValueOf(extra).Pointer() {
		t.Fatal("unchanged Extra map was copied")
	}
	if items[1].(parser.TableItem).Table != table {
		t.Fatal("unchanged table was copied")
	}
}

func TestSanitizer_MapTableUsesTableRules(t *testing.T) {
	// After a JSON round trip a table item is a plain map; it is still walked
	// as a table, so the sheet-name caption is kept and covered cells skipped.
	in := map[string]any{"name": "a.xlsx", "output_format": "json", "json": []any{
		map[string]any{
			parser.DocTypeKey: parser.DocTypeTable,
			"sheet":           "名单" + testPhone,
			"table": map[string]any{
				"caption":     "名单" + testPhone,
				"header_rows": 1,
				"grid":        []any{[]any{map[string]any{"text": "电话"}}, []any{map[string]any{"text": testPhone}}},
			},
		},
	}}
	out := invokeSanitizer(t, in)
	ti, ok := out["json"].([]parser.DocItem)[0].(parser.TableItem)
	if !ok {
		t.Fatalf("item = %T, want TableItem", out["json"].([]parser.DocItem)[0])
	}
	if ti.Table.Caption != "名单"+testPhone || ti.Table.Grid[1][0].Text != phoneMark || ti.Table.HeaderRows != 1 {
		t.Fatalf("table = %+v", ti.Table)
	}
}
