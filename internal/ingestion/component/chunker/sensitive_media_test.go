package chunker

import (
	"context"
	"os"
	"ragflow/internal/sensitive"
	"testing"
	"time"
)

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
