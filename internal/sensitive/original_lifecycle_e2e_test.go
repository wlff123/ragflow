//go:build e2e

package sensitive_test

import (
	"os"
	"ragflow/internal/server"
	"testing"
)

func runOriginalDeleteLifecycle237(t *testing.T, a *acceptance237, modelID, prose string) {
	config := os.Getenv("RAGFLOW_ACCEPTANCE_SERVER_CONFIG")
	if config == "" {
		t.Skip("RAGFLOW_ACCEPTANCE_SERVER_CONFIG is required for private object verification")
	}
	// Match the server's working directory for relative rules/resource paths.
	t.Chdir("../..")
	if err := server.Init(config); err != nil {
		t.Fatal(err)
	}
	p := server.GetSensitiveProcessor()
	if p == nil || p.Originals == nil {
		t.Fatal("private store not configured")
	}
	for _, scope := range []string{"document", "dataset"} {
		t.Run(scope, func(t *testing.T) {
			a.t = t
			ds := a.call("POST", "/datasets", map[string]any{"name": "private deletion " + scope, "parse_type": 1, "parser_id": "general", "embedding_model": modelID})
			if !success237(ds) {
				t.Fatalf("create: %v", ds)
			}
			kb := object237(ds["data"])["id"].(string)
			doc := uploaded237(t, a.upload(kb, "delete-me.txt", []byte(prose+"13812345678"), ""))
			id := doc["id"].(string)
			location, _ := doc["location"].(string)
			if location == "" {
				t.Fatal("private locator missing")
			}
			exists, err := p.Originals.Exists(t.Context(), location)
			if err != nil || !exists {
				t.Fatalf("original absent before deletion: %v", err)
			}
			path := "/datasets/" + kb + "/documents"
			body := map[string]any{"ids": []string{id}}
			if scope == "dataset" {
				path = "/datasets"
				body = map[string]any{"ids": []string{kb}}
			}
			result := a.call("DELETE", path, body)
			if !success237(result) {
				t.Fatalf("delete: %v", result)
			}
			countKey := "deleted"
			if scope == "dataset" {
				countKey = "success_count"
			}
			if object237(result["data"])[countKey] != float64(1) {
				t.Fatalf("database deletion not confirmed: %v", result)
			}
			exists, err = p.Originals.Exists(t.Context(), location)
			if err != nil || exists {
				t.Fatalf("original remains after %s deletion: exists=%v err=%v", scope, exists, err)
			}
		})
	}
}
