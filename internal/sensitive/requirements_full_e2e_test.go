//go:build e2e

package sensitive_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Additional PDF acceptance checks against the real API. A failing requirement
// is retained as evidence, including differences from the design document.
func runExtendedRequirements237(t *testing.T, a *acceptance237, kb, modelID, prose string) {
	const phone = "13812345678"
	ids := map[string]string{"dataset_id": kb}
	defer func() {
		b, _ := json.MarshalIndent(ids, "", "  ")
		if err := os.WriteFile(filepath.Join(a.out, "extended-ids.json"), b, 0600); err != nil {
			t.Error(err)
		}
	}()
	t.Run("configuration_validation_matrix", func(t *testing.T) {
		a.t = t
		for _, config := range []string{`{"enabled":"true"}`, `{"enabled":1}`, `{"enabled":true,"unknown":false}`, `[]`, `null`} {
			result := a.upload(kb, "invalid-config.txt", []byte(prose), config)
			if success237(result) {
				t.Errorf("invalid configuration accepted: %s", config)
			}
		}
	})
	t.Run("document_security_flag_cannot_be_patched", func(t *testing.T) {
		a.t = t
		doc := uploaded237(t, a.upload(kb, "immutable-security.txt", []byte(prose+phone), ""))
		result := a.call("PATCH", "/datasets/"+kb+"/documents/"+doc["id"].(string), map[string]any{"security_config": map[string]any{"enabled": false}})
		if success237(result) {
			t.Log("PATCH returned success; verify the security flag was not changed")
		}
		listed := a.call("GET", "/datasets/"+kb+"/documents", nil)
		rows, _ := object237(listed["data"])["docs"].([]any)
		found := false
		for _, row := range rows {
			d := object237(row)
			if d["id"] == doc["id"] {
				found = true
				if d["security_processing_enabled"] != true {
					t.Error("document security flag changed")
				}
			}
		}
		if !found {
			t.Error("document missing after PATCH")
		}
	})
	t.Run("dataset_default_changes_only_future_uploads", func(t *testing.T) {
		a.t = t
		ds := a.call("POST", "/datasets", map[string]any{"name": "default isolation", "parse_type": 1, "parser_id": "general", "embedding_model": modelID})
		if !success237(ds) {
			t.Fatal("dataset creation failed")
		}
		id := object237(ds["data"])["id"].(string)
		first := uploaded237(t, a.upload(id, "before.txt", []byte(prose), ""))
		if !success237(a.call("PUT", "/datasets/"+id, map[string]any{"security_config": map[string]any{"default_enabled": false, "enforced": false}})) {
			t.Fatal("default update failed")
		}
		second := uploaded237(t, a.upload(id, "after.txt", []byte(prose), ""))
		explicit := uploaded237(t, a.upload(id, "explicit.txt", []byte(prose), `{"enabled":true}`))
		if first["security_processing_enabled"] != true || second["security_processing_enabled"] != false || explicit["security_processing_enabled"] != true {
			t.Error("default inheritance or explicit override incorrect")
		}
		listed := a.call("GET", "/datasets/"+id+"/documents", nil)
		rows, _ := object237(listed["data"])["docs"].([]any)
		found := false
		for _, row := range rows {
			d := object237(row)
			if d["id"] == first["id"] {
				found = true
				if d["security_processing_enabled"] != true {
					t.Error("existing document flag changed")
				}
			}
		}
		if !found {
			t.Error("old document missing")
		}
	})
	t.Run("failed_security_document_cannot_view_chunks", func(t *testing.T) {
		a.t = t
		doc := uploaded237(t, a.upload(kb, "only-sensitive.txt", []byte(phone), ""))
		id := doc["id"].(string)
		ids["invalid_document_id"] = id
		state := a.parse(kb, id)
		if state["ingestion_status"] != "FAILED" || state["security_processed"] != false || state["sensitive_replacement_count"] != nil {
			t.Errorf("unexpected security failure state: %v", state)
		}
		if success237(a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)) {
			t.Error("failed document chunks readable")
		}
	})
	t.Run("regex_boundaries_preserve_nonmatching_identifiers", func(t *testing.T) {
		a.t = t
		value := "A13987654321B"
		doc := uploaded237(t, a.upload(kb, "boundary.txt", []byte(prose+value), ""))
		id := doc["id"].(string)
		state := a.parse(kb, id)
		if state["ingestion_status"] != "COMPLETED" || state["sensitive_replacement_count"] != float64(0) {
			t.Error("nonmatching identifier falsely replaced")
		}
		got := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		b, _ := json.Marshal(got)
		if !bytes.Contains(b, []byte(value)) {
			t.Error("nonmatching identifier lost")
		}
	})
	t.Run("structured_import_rejects_security_configuration", func(t *testing.T) {
		a.t = t
		for _, source := range []string{"local", "web", "empty"} {
			for _, config := range []string{`{"enabled":true}`, `{"enabled":false}`, `null`, `{}`} {
				var buf bytes.Buffer
				form := multipart.NewWriter(&buf)
				part, err := form.CreateFormFile("file", "structured.csv")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = part.Write([]byte("name,notes\nexample," + prose + phone + "\n"))
				_ = form.WriteField("import_type", "structured")
				_ = form.WriteField("security_config", config)
				_ = form.Close()
				var result map[string]any
				if source == "empty" {
					result = a.call("POST", "/datasets/"+kb+"/documents?type=empty", map[string]any{
						"name": "structured", "import_type": "structured", "security_config": json.RawMessage(config),
					})
				} else {
					result = a.request("POST", "/datasets/"+kb+"/documents?type="+source, form.FormDataContentType(), &buf, true)
				}
				b, _ := json.Marshal(result)
				if success237(result) || !bytes.Contains(b, []byte("SECURITY_PROCESSING_UNSUPPORTED_FOR_IMPORT_TYPE")) {
					t.Errorf("PDF import-type rejection missing: source=%s config=%s code=%v", source, config, result["code"])
				}
			}
		}
	})
	t.Run("public_web_download_cleans_content", func(t *testing.T) {
		a.t = t
		// Public HTTP fixture service decodes our synthetic body; no real secret is sent.
		remoteURL := "https://httpbingo.org/base64/" + base64.StdEncoding.EncodeToString([]byte(prose+phone))
		var buf bytes.Buffer
		form := multipart.NewWriter(&buf)
		_ = form.WriteField("name", "public-web.txt")
		_ = form.WriteField("url", remoteURL)
		_ = form.WriteField("security_config", `{"enabled":true}`)
		_ = form.Close()
		result := a.request("POST", "/datasets/"+kb+"/documents?type=web", form.FormDataContentType(), &buf, true)
		if !success237(result) {
			t.Fatalf("public web upload failed: %v", result)
		}
		doc := object237(result["data"])
		if rows, ok := result["data"].([]any); ok && len(rows) > 0 {
			doc = object237(rows[0])
		}
		id, _ := doc["id"].(string)
		if id == "" {
			t.Fatal("web document id absent")
		}
		ids["web_document_id"] = id
		state := a.parse(kb, id)
		if state["ingestion_status"] != "COMPLETED" || state["sensitive_replacement_count"] != float64(1) {
			t.Errorf("web result: %v", state)
		}
		got := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		b, _ := json.Marshal(got)
		if !success237(got) || bytes.Contains(b, []byte(phone)) || !strings.Contains(string(b), "敏感信息已移除") {
			t.Error("web chunks not safely cleaned")
		}
	})
}
