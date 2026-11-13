package component

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"ragflow/internal/entity"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sensitive"
)

func sensitiveParserContext(t *testing.T, name string) (context.Context, *sensitive.Session) {
	t.Helper()
	f, err := os.Open("../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p := &sensitive.Processor{Engine: e, MinimumCharacters: 20, MinimumRatio: .05}
	ctx, session, err := sensitive.WithSession(context.Background(), p, "doc", "round", name)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, session
}

func TestSensitiveParserRemovesCrossItemValueAndMedia(t *testing.T) {
	ctx, session := sensitiveParserContext(t, "guide.txt")
	out := map[string]any{"json": []parser.DocItem{
		parser.TextItem{Text: "这是足够长的正常业务描述内容需要完整保留在知识库中，电话13812"},
		parser.TextItem{Text: "345678以及后续的操作说明"},
		parser.ImageItem{Text: "图示13812345678", Image: "raw-image", Sheet: "客户13812345678"},
	}}
	if err := cleanParserOutput(ctx, out); err != nil {
		t.Fatal(err)
	}
	if !session.Parsed || session.Result.Count != 2 {
		t.Fatalf("result %+v", session.Result)
	}
	items := out["json"].([]parser.DocItem)
	for _, item := range items {
		m := item.ToMap()
		if m["image"] != nil || m["media_ref"] != nil {
			t.Fatal("media retained")
		}
		if text, _ := m["text"].(string); strings.Contains(text, "13812345678") {
			t.Fatal("raw phone retained")
		}
	}
}

func TestSensitiveEmailKeepsBodyHeaderBoundary(t *testing.T) {
	for _, ending := range []string{"", "\n"} {
		ctx, session := sensitiveParserContext(t, "message.eml")
		source := "From: sender@example.invalid\r\nSubject: Guide\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nOrdinary operational documentation that remains searchable. 13812345678" + ending
		parsed := parser.NewEmailParser().ParseWithResult(ctx, "message.eml", []byte(source))
		if parsed.Err != nil {
			t.Fatal(parsed.Err)
		}
		out := map[string]any{"json": parsed.JSON, "file": parsed.File}
		if err := cleanParserOutput(ctx, out); err != nil {
			t.Fatal(err)
		}
		if session.Result.Count != 1 {
			t.Fatalf("ending %q: count=%d", ending, session.Result.Count)
		}
		for _, item := range out["json"].([]parser.DocItem) {
			if err := session.Processor.Engine.ScanValue(ctx, item.ToMap()); err != nil {
				t.Fatalf("ending %q: %v", ending, err)
			}
		}
	}
}

func TestSensitiveParserTableAndUnsafeExtras(t *testing.T) {
	ctx, _ := sensitiveParserContext(t, "sheet.xlsx")
	table := &entity.TableData{Grid: [][]entity.TableCell{{{Text: "这是足够长的正常业务说明内容用于通过有效内容阈值检查"}, {Text: "13812345678"}}}}
	out := map[string]any{"json": []parser.DocItem{parser.TableItem{Table: table, Sheet: "客户13812345678"}}}
	if err := cleanParserOutput(ctx, out); err != nil {
		t.Fatal(err)
	}
	got := out["json"].([]parser.DocItem)[0].ToMap()["table"].(*entity.TableData)
	if got.Grid[0][1].Text != "[敏感信息已移除：手机号]" || table.Grid[0][1].Text != "13812345678" {
		t.Fatal("table clone/replacement incorrect")
	}
	out = map[string]any{"json": []parser.DocItem{parser.TextItem{Text: "这是足够长的正常业务说明内容用于通过有效内容阈值检查", Extra: map[string]any{"page_number": "13812345678"}}}}
	if err := cleanParserOutput(ctx, out); sensitive.Reason(err) != "SP_STRUCTURE_INVALID" {
		t.Fatal("untyped system field bypass", err)
	}
}

func TestSensitiveJSONSourcePreservesEscapedValueContext(t *testing.T) {
	ctx, session := sensitiveParserContext(t, "data.json")
	result := parser.NewJSONParser().ParseWithResult(ctx, "data.json", []byte(`[{"password":"abc\u0064efgh1234","note":"这是足够长的正常业务说明内容用于通过有效内容阈值检查"},"13812345678"]`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	out := map[string]any{"json": result.JSON, "file": result.File}
	if err := cleanParserOutput(ctx, out); err != nil {
		t.Fatal(err)
	}
	if session.Result.Count != 2 {
		t.Fatalf("count %d", session.Result.Count)
	}
}

type parserOriginalFixture struct{ text string }

func (f parserOriginalFixture) Check(context.Context) error                  { return nil }
func (f parserOriginalFixture) Exists(context.Context, string) (bool, error) { return true, nil }
func (f parserOriginalFixture) OpenOriginal(context.Context, string) (*sensitive.Original, error) {
	return &sensitive.Original{Body: io.NopCloser(strings.NewReader(f.text)), Name: "guide.txt", Size: int64(len(f.text))}, nil
}
func (f parserOriginalFixture) PutOriginal(context.Context, string, string, []byte) error {
	panic("unexpected write")
}
func (f parserOriginalFixture) Delete(context.Context, string) error { panic("unexpected delete") }

func TestSensitiveParserInvokeSealsFinalOutput(t *testing.T) {
	ctx, session := sensitiveParserContext(t, "guide.txt")
	session.DatasetID = "kb"
	session.OriginalLocation = "kb/doc/source"
	session.Processor.Originals = parserOriginalFixture{text: strings.Repeat("Ordinary technical documentation remains available. ", 4) + " Contact 13812345678"}
	component := &ParserComponent{setups: defaultSetups()}
	out, err := component.Invoke(ctx, nil, map[string]any{"name": "guide.txt", "doc_id": "doc", "bucket": "kb", "path": "kb/doc/source"})
	if err != nil {
		t.Fatal(err)
	}
	if out["file_type"] != "txt" || out["doc_id"] != "doc" {
		t.Fatalf("missing output routing fields")
	}
	// The real canvas adds state and progress fields between stages.
	out["state"] = map[string]any{"Parser:1": map[string]any{"result": "runtime snapshot"}}
	out["__cpn_id__"] = "Parser:1"
	if err := session.RequireOutput(out); err != nil {
		t.Fatal(err)
	}
	if session.Result.Count != 1 {
		t.Fatalf("count=%d", session.Result.Count)
	}
}
