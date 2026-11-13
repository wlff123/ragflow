package chunker

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"ragflow/internal/agent/runtime"
	"ragflow/internal/parser/parser"
	"ragflow/internal/sensitive"
)

const testPlaceholder = "[敏感信息已移除：手机号]"

func assertWholePlaceholders(t *testing.T, parts []string, expected int) {
	t.Helper()
	count := 0
	for _, part := range parts {
		count += strings.Count(part, testPlaceholder)
		plain := strings.ReplaceAll(part, testPlaceholder, "")
		if strings.ContainsAny(plain, "[]敏感信息已移除手机号") {
			t.Fatalf("fragmented placeholder: %q", part)
		}
	}
	if count < expected {
		t.Fatalf("lost placeholders: count=%d want>=%d parts=%q", count, expected, parts)
	}
}

func TestSensitiveRegisteredChunkersPreservePlaceholders(t *testing.T) {
	f, err := os.Open("../../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TokenChunker", "GeneralChunker"} {
		for _, delimiter := range []string{"：", "`：`", "`[：号]`"} {
			for _, overlap := range []float64{0, 50} {
				t.Run(fmt.Sprintf("%s/%s/overlap_%g", name, delimiter, overlap), func(t *testing.T) {
					factory, _, _, ok := runtime.DefaultRegistry.Lookup(name)
					if !ok {
						t.Fatal("missing factory")
					}
					component, err := factory("test", map[string]any{"chunk_token_size": 3, "delimiters": []string{delimiter}, "overlapped_percent": overlap})
					if err != nil {
						t.Fatal(err)
					}
					ctx, session, err := sensitive.WithSession(t.Context(), &sensitive.Processor{Engine: e}, "doc", "run", "guide.txt")
					if err != nil {
						t.Fatal(err)
					}
					body := "alpha " + testPlaceholder + testPlaceholder + " beta " + testPlaceholder + " gamma"
					input := map[string]any{"name": "guide.txt", "file_type": "txt", "output_format": "text", "text": body}
					if name == "GeneralChunker" {
						parsed := parser.NewTextParser().ParseWithResult(t.Context(), "guide.txt", []byte(body))
						input = map[string]any{"name": "guide.txt", "file_type": "txt", "output_format": "json", "json": parsed.JSON}
					}
					if err := session.SealOutput(input); err != nil {
						t.Fatal(err)
					}
					out, err := component.Invoke(ctx, nil, input)
					if err != nil {
						t.Fatal(err)
					}
					assertWholePlaceholders(t, outputTexts(t, out), 3)
				})
			}
		}
	}
}

func TestPlaceholderHardCutsAndOverlap(t *testing.T) {
	body := "alpha " + testPlaceholder + testPlaceholder + " beta"
	for cap := 1; cap <= 24; cap++ {
		var parts []string
		for _, chunk := range hardSplitPiece(body, "text", cap) {
			parts = append(parts, chunk.Text)
		}
		assertWholePlaceholders(t, parts, 2)
		if strings.Join(parts, "") != body {
			t.Fatal("BPE split lost text")
		}
		parts = hardSplitByTokens(body, cap)
		assertWholePlaceholders(t, parts, 2)
		if strings.Join(parts, "") != body {
			t.Fatal("title split lost text")
		}
		parts = nil
		for _, chunk := range hardSplitPieceByteLoop(body, "text", cap) {
			parts = append(parts, chunk.Text)
		}
		assertWholePlaceholders(t, parts, 2)
		if strings.Join(parts, "") != body {
			t.Fatal("fallback split lost text")
		}
		for percent := 1.; percent < 100; percent++ {
			overlap, _ := computeOverlapPrefix(body, percent)
			assertWholePlaceholders(t, []string{overlap}, 0)
			fit, _ := overlapFitPrefix(overlap, "end", cap)
			assertWholePlaceholders(t, []string{fit}, 0)
		}
	}
}
