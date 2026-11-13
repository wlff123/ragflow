package sensitive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltInPipelineAdmission(t *testing.T) {
	files, err := filepath.Glob("../ingestion/pipeline/template/ingestion_pipeline_*.json")
	if err != nil || len(files) != 12 {
		t.Fatalf("expected 12 templates: %d %v", len(files), err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var template struct {
				DSL json.RawMessage `json:"dsl"`
			}
			if err = json.Unmarshal(b, &template); err != nil {
				t.Fatal(err)
			}
			if err = ValidatePipeline(template.DSL, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPipelineRejectsBypassAndErrorRecovery(t *testing.T) {
	b, err := os.ReadFile("../ingestion/pipeline/template/ingestion_pipeline_general.json")
	if err != nil {
		t.Fatal(err)
	}
	var template struct {
		DSL json.RawMessage `json:"dsl"`
	}
	if err = json.Unmarshal(b, &template); err != nil {
		t.Fatal(err)
	}
	for _, override := range []map[string]any{
		{"File": map[string]any{"exception_method": "comment", "exception_default_value": "raw"}},
		{"File": map[string]any{"binary": "raw"}},
		{"File": map[string]any{"outputs": map[string]any{"text": map[string]any{"value": "raw"}}}},
	} {
		if Reason(ValidatePipeline(template.DSL, override)) != "SP_PIPELINE_NOT_ALLOWED" {
			t.Fatal("accepted unsafe override")
		}
	}
	// Keys that name no graph node never reach a component, as in canvas.
	if err = ValidatePipeline(template.DSL, map[string]any{"metadata": map[string]any{"enabled": true}, "llm_id": "x"}); err != nil {
		t.Fatalf("rejected non-component parser_config keys: %v", err)
	}
	var graph map[string]any
	if json.Unmarshal(template.DSL, &graph) != nil {
		t.Fatal("invalid fixture")
	}
	nodes := graph["components"].(map[string]any)
	nodes["File"].(map[string]any)["downstream"] = []string{"Tokenizer:LegalReadersDecide"}
	modified, _ := json.Marshal(graph)
	if Reason(ValidatePipeline(modified, nil)) != "SP_PIPELINE_NOT_ALLOWED" {
		t.Fatal("parser bypass accepted")
	}
}
