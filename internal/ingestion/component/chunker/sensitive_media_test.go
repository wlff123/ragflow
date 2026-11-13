package chunker

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"ragflow/internal/agent/runtime"
	"ragflow/internal/ingestion/component"
	"ragflow/internal/sensitive"
	"strings"
	"testing"
	"time"
)

type htmlOriginal struct{ sensitive.OriginalStorage }

func (htmlOriginal) OpenOriginal(context.Context, string) (*sensitive.Original, error) {
	return &sensitive.Original{Body: io.NopCloser(strings.NewReader("<p>Contact 13812345678</p><p>Next steps describe ordinary operational documentation.</p>")), Name: "guide.html"}, nil
}

func TestSensitiveHTMLParserToTokenChunker(t *testing.T) {
	f, err := os.Open("../../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, session, err := sensitive.WithSession(t.Context(), &sensitive.Processor{
		Engine: e, Originals: htmlOriginal{}, MinimumCharacters: 20, MinimumRatio: .05,
	}, "doc", "run", "guide.html")
	if err != nil {
		t.Fatal(err)
	}
	session.DatasetID, session.OriginalLocation = "kb", "kb/doc/original"
	parser, err := component.NewParserComponent(nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Invoke(ctx, nil, map[string]any{"name": "guide.html", "doc_id": "doc", "bucket": "kb", "path": session.OriginalLocation})
	if err != nil {
		t.Fatal(err)
	}
	factory, _, _, ok := runtime.DefaultRegistry.Lookup("TokenChunker")
	if !ok {
		t.Fatal("TokenChunker not registered")
	}
	chunker, err := factory("test", map[string]any{"chunk_token_size": 128})
	if err != nil {
		t.Fatal(err)
	}
	out, err := chunker.Invoke(ctx, nil, parsed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "13812345678") || !strings.Contains(string(encoded), "[敏感信息已移除：手机号]") || session.Result.Count != 1 {
		t.Fatal("paragraph phone was not cleaned exactly once")
	}
}

func TestSensitiveMediaNeverReachesUploader(t *testing.T) {
	f, err := os.Open("../../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	engine, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _, err := sensitive.WithSession(context.Background(), &sensitive.Processor{Engine: engine}, "doc", "run", "guide.pdf")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	upload := func(context.Context, string, string, []byte) (string, error) { calls++; return "unexpected", nil }
	chunks := []map[string]any{
		{"id": "one", "image": "invalid base64", "media_ref": map[string]any{"key": "raw"}},
		{"id": "two", "img_id": "previous-image", "image": "raw"},
	}
	out, err := uploadChunkMedia(ctx, chunks, upload, "kb", "doc")
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range out {
		if chunk["image"] != nil || chunk["media_ref"] != nil || chunk["img_id"] != "" {
			t.Fatal("media survived")
		}
	}
	direct := map[string]any{"image": "raw"}
	if err := uploadChunkImage(ctx, direct, upload, "kb"); err != nil {
		t.Fatal(err)
	}
	if id, err := uploadOneImage(ctx, upload, "kb", "chunk", []byte("raw")); err != nil || id != "" {
		t.Fatal("direct upload survived")
	}
	if calls != 0 {
		t.Fatalf("uploader called %d times", calls)
	}
}
