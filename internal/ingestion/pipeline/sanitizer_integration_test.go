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

//go:build integration

package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	componentpkg "ragflow/internal/ingestion/component"
	_ "ragflow/internal/ingestion/component/chunker"
	"ragflow/internal/ingestion/component/schema"
)

// Synthetic sensitive values used by the Sanitizer pipeline tests.
var sanitizerRawValues = []string{
	"13800138000",                      // 手机号
	"110101199003071234",               // 身份证
	"abcd1234efgh",                     // 密钥类 (password value)
	"root:Passw0rd@db.local",           // 数据库密码
	"ghp_" + strings.Repeat("Ab1", 12), // GitHub PAT (Classic)
}

const (
	sanitizerParserID  = "Parser:HipSignsRhyme"
	sanitizerChunkerID = "GeneralChunker:SixApplesFall"
	sanitizerNodeID    = "Sanitizer:Default"
)

// recordingEmbedder embeds like fixedEmbedder and records every text it was
// asked to embed, so the test can check the embedding input.
type recordingEmbedder struct {
	fixedEmbedder
	mu    sync.Mutex
	texts []string
}

func (e *recordingEmbedder) Encode(ctx context.Context, texts []string) ([]componentpkg.EmbeddingResult, error) {
	e.mu.Lock()
	e.texts = append(e.texts, texts...)
	e.mu.Unlock()
	return e.fixedEmbedder.Encode(ctx, texts)
}

// generalTemplateWithSanitizer returns the built-in General template with a
// Sanitizer node inserted between Parser and GeneralChunker.
func generalTemplateWithSanitizer(t *testing.T, insert bool) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootFromPipelineTest(t), "internal", "ingestion", "pipeline", "template", "ingestion_pipeline_general.json"))
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	if !insert {
		return raw
	}
	var tpl map[string]any
	if err := json.Unmarshal(raw, &tpl); err != nil {
		t.Fatal(err)
	}
	components := tpl["dsl"].(map[string]any)["components"].(map[string]any)
	parserNode := components[sanitizerParserID].(map[string]any)
	chunkerNode := components[sanitizerChunkerID].(map[string]any)
	parserNode["downstream"] = []any{sanitizerNodeID}
	chunkerNode["upstream"] = []any{sanitizerNodeID}
	components[sanitizerNodeID] = map[string]any{
		"downstream": []any{sanitizerChunkerID},
		"upstream":   []any{sanitizerParserID},
		"obj":        map[string]any{"component_name": componentpkg.ComponentNameSanitizer, "params": map[string]any{}},
	}
	out, err := json.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func runSanitizerPipeline(t *testing.T, dsl []byte, filename, content string) (map[string]any, *recordingEmbedder) {
	t.Helper()
	RequireTokenizerPool(t)
	mem := withRealTemplateDeps(t)
	docID := seedTemplateDocument(t, mem, filename, "test-bucket", "fixtures/"+filename, content)

	pipe, err := NewPipelineFromDSL(dsl, "sanitizer-"+strings.ReplaceAll(t.Name(), "/", "-"))
	if err != nil {
		t.Fatalf("NewPipelineFromDSL: %v", err)
	}
	emb := &recordingEmbedder{}
	attachEmbedderFactory(t, pipe, emb)
	out, err := pipe.Run(t.Context(), map[string]any{"doc_id": docID, "kb_id": "test-kb"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out, emb
}

// leakedValues returns the raw values found anywhere in v (any string field,
// at any depth).
func leakedValues(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T for leak check: %v", v, err)
	}
	s := string(b)
	var leaked []string
	for _, raw := range sanitizerRawValues {
		if strings.Contains(s, raw) {
			leaked = append(leaked, raw)
		}
	}
	return leaked
}

func checkSanitizedEmbedding(t *testing.T, texts []string) {
	t.Helper()
	if leaked := leakedValues(t, texts); len(leaked) > 0 {
		t.Fatalf("raw values in embedding input: %v", leaked)
	}
	for _, text := range texts {
		if strings.Contains(text, "[敏感信息已移除：手机号]") {
			return
		}
	}
	t.Fatal("embedding inputs did not contain the sanitized document body")
}

func finalChunks(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	payload := terminalPayloadFromRunOutput(t, out, "Tokenizer:LegalReadersDecide")
	chunks, ok := schema.ChunkCarrierToMaps(payload["chunks"])
	if !ok || len(chunks) == 0 {
		t.Fatalf("chunks = %T %v", payload["chunks"], payload["chunks"])
	}
	return chunks
}

const sanitizerTextFixture = "客户联系人：张三，手机号 13800138000，身份证 110101199003071234。\n\n" +
	"数据库配置：\npassword: abcd1234efgh\ndsn=mysql://root:Passw0rd@db.local:3306/app\n\n" +
	"部署令牌 ghp_Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1Ab1 仅用于测试。"

// TestPipelineRun_Sanitizer_TextDocument runs File -> Parser -> Sanitizer ->
// GeneralChunker -> Tokenizer with real components and checks that no raw
// value reaches the chunks, their full-text fields or the embedding input.
func TestPipelineRun_Sanitizer_TextDocument(t *testing.T) {
	out, emb := runSanitizerPipeline(t, generalTemplateWithSanitizer(t, true), "sanitizer.txt", sanitizerTextFixture)

	chunks := finalChunks(t, out)
	if leaked := leakedValues(t, chunks); len(leaked) > 0 {
		t.Fatalf("raw values in indexed chunks: %v", leaked)
	}
	checkSanitizedEmbedding(t, emb.texts)
	all := ""
	for _, c := range chunks {
		text, _ := c["text"].(string)
		all += text
		if ltks, _ := c["content_ltks"].(string); ltks == "" {
			t.Fatalf("chunk without content_ltks: %v", c)
		}
	}
	for _, mark := range []string{
		"[敏感信息已移除：手机号]",
		"[敏感信息已移除：身份证]",
		"password: [敏感信息已移除：密钥类]",
		"dsn=[敏感信息已移除：数据库密码]",
		"[敏感信息已移除：GitHub Personal Access Token（Classic）]",
	} {
		if !strings.Contains(all, mark) {
			t.Fatalf("missing %q in chunk text:\n%s", mark, all)
		}
	}
	if !strings.Contains(all, "客户联系人：张三") || !strings.Contains(all, "仅用于测试") {
		t.Fatalf("ordinary text lost:\n%s", all)
	}

	state := stateFromRunOutput(t, out)
	node, ok := state[sanitizerNodeID]
	if !ok {
		t.Fatalf("missing %s in pipeline state", sanitizerNodeID)
	}
	report, ok := node[schema.KeySanitizeReport].(schema.SanitizeReport)
	if !ok || report.ReplacementCount != 5 || report.RulesSource != "builtin" {
		t.Fatalf("report = %#v", node[schema.KeySanitizeReport])
	}
	if node["output_format"] != "json" || node["name"] != "sanitizer.txt" {
		t.Fatalf("envelope not passed through: format=%v name=%v", node["output_format"], node["name"])
	}
	t.Logf("chunks=%d embedding_inputs=%d report=%+v", len(chunks), len(emb.texts), report)
}

// TestPipelineRun_Sanitizer_JSONDocument checks a JSON file: values are
// replaced and the chunk text is still valid JSON.
func TestPipelineRun_Sanitizer_JSONDocument(t *testing.T) {
	content := `{"user":"张三","phone":13800138000,"password":"abcd1234efgh","tags":["客户","110101199003071234"]}`
	out, emb := runSanitizerPipeline(t, generalTemplateWithSanitizer(t, true), "sanitizer.json", content)

	chunks := finalChunks(t, out)
	if leaked := leakedValues(t, chunks); len(leaked) > 0 {
		t.Fatalf("raw values in indexed chunks: %v", leaked)
	}
	checkSanitizedEmbedding(t, emb.texts)
	text, _ := chunks[0]["text"].(string)
	var v map[string]any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("chunk text is not valid JSON: %v\n%s", err, text)
	}
	if v["phone"] != "[敏感信息已移除：手机号]" || v["password"] != "[敏感信息已移除：密钥类]" || v["user"] != "张三" {
		t.Fatalf("unexpected JSON values: %v", v)
	}
	t.Logf("chunk=%s", text)
}

// TestPipelineRun_WithoutSanitizer_Control runs the unchanged General template
// on the same document: raw values do reach the chunks. This proves the leak
// checks above are meaningful and that the pipeline without the node behaves
// as before.
func TestPipelineRun_WithoutSanitizer_Control(t *testing.T) {
	out, _ := runSanitizerPipeline(t, generalTemplateWithSanitizer(t, false), "control.txt", sanitizerTextFixture)
	if leaked := leakedValues(t, finalChunks(t, out)); len(leaked) != len(sanitizerRawValues) {
		t.Fatalf("control run should keep all raw values, found %v", leaked)
	}
	if _, ok := stateFromRunOutput(t, out)[sanitizerNodeID]; ok {
		t.Fatal("control run unexpectedly has a Sanitizer node")
	}
}
