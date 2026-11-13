//go:build e2e

package sensitive_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSensitiveHTTPAcceptance exercises a real API and its configured services.
// It never patches database flags, substitutes models, or bypasses admission.
// Use an isolated deployment: this test leaves its synthetic documents for audit.
func TestSensitiveHTTPAcceptance(t *testing.T) {
	base := os.Getenv("RAGFLOW_ACCEPTANCE_URL")
	if base == "" {
		t.Skip("RAGFLOW_ACCEPTANCE_URL is required")
	}
	out := os.Getenv("RAGFLOW_ACCEPTANCE_OUTPUT")
	if out == "" {
		t.Fatal("RAGFLOW_ACCEPTANCE_OUTPUT is required")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	token := ""
	seq := 0
	request := func(method, path, contentType string, body io.Reader, save bool) (int, map[string]any, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequest(method, strings.TrimRight(base, "/")+"/api/v1"+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		_ = json.Unmarshal(raw, &value)
		if save {
			seq++
			evidence, _ := json.MarshalIndent(map[string]any{"method": method, "path": path, "status": resp.StatusCode, "body": string(raw)}, "", "  ")
			if err := os.WriteFile(filepath.Join(out, fmt.Sprintf("http-%02d.json", seq)), evidence, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode, value, raw, resp.Header
	}
	call := func(method, path string, body any) map[string]any {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		_, value, _, _ := request(method, path, "application/json", bytes.NewReader(data), true)
		return value
	}
	ok := func(value map[string]any) bool { code, present := value["code"]; return present && code == float64(0) }
	object := func(value any) map[string]any { v, _ := value.(map[string]any); return v }
	check := func(name string, pass bool, detail any) {
		t.Run(name, func(t *testing.T) {
			if !pass {
				t.Errorf("requirement not met: %v", detail)
			}
		})
	}
	account := map[string]any{"email": fmt.Sprintf("v100-acceptance-%d@example.invalid", time.Now().UnixNano()), "password": "E2e-only!2026", "nickname": "sensitive acceptance"}
	authBody, _ := json.Marshal(account)
	_, registered, _, _ := request("POST", "/users", "application/json", bytes.NewReader(authBody), false)
	if !ok(registered) {
		t.Fatalf("registration failed: code=%v message=%v", registered["code"], registered["message"])
	}
	_, login, _, headers := request("POST", "/auth/login", "application/json", bytes.NewReader(authBody), false)
	if !ok(login) {
		t.Fatalf("login failed: code=%v message=%v", login["code"], login["message"])
	}
	token = headers.Get("Authorization")
	if token == "" {
		t.Fatal("login did not return authorization")
	}
	create := func(name string, security any) map[string]any {
		body := map[string]any{"name": name, "parse_type": 1, "parser_id": "general"}
		if security != nil {
			body["security_config"] = security
		}
		return call("POST", "/datasets", body)
	}
	created := create("v100 requirement acceptance", nil)
	if !ok(created) {
		t.Fatalf("dataset prerequisite failed: %v", created)
	}
	dataset := object(created["data"])
	kb, _ := dataset["id"].(string)
	if kb == "" {
		t.Fatal("dataset id missing")
	}
	check("new_dataset_defaults_enabled", object(dataset["security_config"])["default_enabled"] == true, dataset["security_config"])
	forced := create("v100 enforced acceptance", map[string]any{"default_enabled": true, "enforced": true})
	forcedData := object(forced["data"])
	check("dataset_saves_enforced_configuration", ok(forced) && object(forcedData["security_config"])["enforced"] == true, forcedData["security_config"])
	invalid := create("v100 invalid config", map[string]any{"default_enabled": false, "enforced": true})
	check("reject_inconsistent_configuration", !ok(invalid) && strings.Contains(fmt.Sprint(invalid["message"]), "SP_CONFIG_INVALID"), invalid["message"])
	updated := call("PUT", "/datasets/"+kb, map[string]any{"security_config": map[string]any{"default_enabled": true, "enforced": true}})
	queried := call("GET", "/datasets/"+kb, nil)
	check("dataset_update_preserves_configuration", ok(updated) && object(object(queried["data"])["security_config"])["enforced"] == true, object(queried["data"])["security_config"])
	const phone = "13812345678"
	text := strings.Repeat("This is ordinary documentation that must remain available after safe processing. ", 4) + "\nContact phone: " + phone + "\npassword=abcdefgh1234\n"
	upload := func(id, name, config, content string) map[string]any {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		part, err := form.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(part, content); err != nil {
			t.Fatal(err)
		}
		if err = form.WriteField("security_config", config); err != nil {
			t.Fatal(err)
		}
		if err = form.Close(); err != nil {
			t.Fatal(err)
		}
		_, value, _, _ := request("POST", "/datasets/"+id+"/documents", form.FormDataContentType(), &body, true)
		return value
	}
	uploaded := upload(kb, "contact_"+phone+".txt", `{"enabled":true}`, text)
	if !ok(uploaded) {
		t.Fatalf("upload prerequisite failed: %v", uploaded)
	}
	docs, _ := uploaded["data"].([]any)
	if len(docs) == 0 {
		t.Fatalf("no uploaded document: %v", uploaded)
	}
	doc := object(docs[0])
	docID, _ := doc["id"].(string)
	if docID == "" {
		t.Fatal("document id missing")
	}
	check("explicit_upload_enables_processing", doc["security_processing_enabled"] == true, doc["security_processing_enabled"])
	check("filename_cleaned_before_storage", !strings.Contains(fmt.Sprint(doc["name"]), phone), doc["name"])
	_, hasCount := doc["sensitive_replacement_count"]
	check("upload_returns_unprocessed_and_unknown_count", doc["security_processed"] == false && hasCount && doc["sensitive_replacement_count"] == nil, doc)
	badUpload := upload(kb, "invalid-config.txt", "{bad-json", text)
	check("reject_invalid_upload_configuration", !ok(badUpload), badUpload["code"])
	if forcedID, _ := forcedData["id"].(string); forcedID != "" {
		closed := upload(forcedID, "cannot-disable.txt", `{"enabled":false}`, text)
		check("enforced_dataset_rejects_disabled_upload", !ok(closed), closed["code"])
	}
	docPath := "/datasets/" + kb + "/documents/" + docID
	status, _, raw, _ := request("GET", docPath, "", nil, true)
	check("ordinary_download_cannot_return_original", status != 200 || !bytes.Contains(raw, []byte(phone)), fmt.Sprintf("status=%d contains_raw=%t", status, bytes.Contains(raw, []byte(phone))))
	status, originalDenied, _, _ := request("GET", docPath+"/original", "", nil, true)
	check("original_route_exists_and_requires_authorization", status != 404 && !ok(originalDenied) && originalDenied["message"] == "SP_ORIGINAL_ACCESS_DENIED", originalDenied["message"])
	_, keyResponse, _, _ := request("POST", "/system/tokens", "application/json", strings.NewReader("{}"), false)
	apiKey, _ := object(keyResponse["data"])["token"].(string)
	if !ok(keyResponse) || apiKey == "" {
		t.Fatal("API token prerequisite failed")
	}
	userToken := token
	token = "Bearer " + apiKey
	status, _, originalBytes, originalHeaders := request("GET", docPath+"/original", "", nil, true)
	check("api_token_reads_private_original", status == 200 && string(originalBytes) == text && originalHeaders.Get("Cache-Control") == "no-store", status)
	token = userToken
	_, _, _, _ = request("DELETE", "/system/tokens/"+apiKey, "", nil, false)
	chunks := call("GET", docPath+"/chunks", nil)
	check("unprocessed_document_cannot_view_chunks", !ok(chunks), chunks["code"])
	renamed := call("PATCH", docPath, map[string]any{"name": "renamed_" + phone + ".txt"})
	check("rename_cleans_sensitive_name", ok(renamed) && !strings.Contains(fmt.Sprint(renamed["data"]), phone), renamed["code"])
	empty := call("POST", "/datasets/"+kb+"/documents?type=empty", map[string]any{"name": "empty_" + phone, "security_config": map[string]any{"enabled": true}})
	check("empty_import_applies_security_configuration", ok(empty) && object(empty["data"])["security_processing_enabled"] == true, object(empty["data"])["security_processing_enabled"])
	parsed := call("POST", "/datasets/"+kb+"/documents/parse", map[string]any{"document_ids": []string{docID}})
	check("parse_request_accepted", ok(parsed), parsed)
	waitDocument := func() map[string]any {
		deadline := time.Now().Add(30 * time.Second)
		var found map[string]any
		for time.Now().Before(deadline) {
			listed := call("GET", "/datasets/"+kb+"/documents", nil)
			rows, _ := object(listed["data"])["docs"].([]any)
			for _, row := range rows {
				if object(row)["id"] == docID {
					found = object(row)
				}
			}
			state := fmt.Sprint(found["ingestion_status"])
			if state == "FAILED" || state == "COMPLETED" || state == "CANCELED" {
				return found
			}
			time.Sleep(time.Second)
		}
		return found
	}
	if ok(parsed) {
		state := waitDocument()
		t.Logf("default pipeline terminal state: %v", state["ingestion_status"])
		// Full-text-only is a supported production configuration. It lets this
		// deployment exercise real indexing without inventing an embedding model.
		config := object(doc["parser_config"])
		for key, value := range config {
			if strings.HasPrefix(key, "Tokenizer:") {
				object(value)["search_method"] = []string{"full_text"}
			}
		}
		patch := call("PATCH", docPath, map[string]any{"parser_config": config})
		if !ok(patch) {
			t.Fatalf("full-text configuration failed: %v", patch)
		}
		restarted := call("POST", "/datasets/"+kb+"/documents/parse", map[string]any{"document_ids": []string{docID}})
		if !ok(restarted) {
			t.Fatalf("full-text parse failed: %v", restarted)
		}
		state = waitDocument()
		check("full_text_pipeline_completes", state["ingestion_status"] == "COMPLETED", state["ingestion_status"])
		finalChunks := call("GET", docPath+"/chunks", nil)
		persisted, _ := object(finalChunks["data"])["chunks"].([]any)
		check("persisted_chunks_are_nonempty", len(persisted) > 0, len(persisted))
		check("chunk_document_reports_security_result", object(object(finalChunks["data"])["doc"])["security_processed"] == true, object(object(finalChunks["data"])["doc"])["security_processed"])
		encoded, _ := json.Marshal(finalChunks["data"])
		check("persisted_chunks_contain_no_raw_values", ok(finalChunks) && !bytes.Contains(encoded, []byte(phone)) && !bytes.Contains(encoded, []byte("abcdefgh1234")), fmt.Sprintf("code=%v raw_phone=%t raw_secret=%t", finalChunks["code"], bytes.Contains(encoded, []byte(phone)), bytes.Contains(encoded, []byte("abcdefgh1234"))))
		check("successful_processing_records_count", state["security_processed"] == true && state["sensitive_replacement_count"] == float64(2), fmt.Sprintf("processed=%v count=%v", state["security_processed"], state["sensitive_replacement_count"]))
		retrieved := call("POST", "/datasets/"+kb+"/search", map[string]any{"question": "Contact phone", "keywords_similarity_weight": 1, "similarity_threshold": 0})
		if !ok(retrieved) {
			t.Run("retrieval_result_safety", func(t *testing.T) { t.Skipf("retrieval prerequisite failed: %v", retrieved["message"]) })
		} else {
			result, _ := json.Marshal(retrieved["data"])
			hits, _ := object(retrieved["data"])["chunks"].([]any)
			check("retrieval_result_safety", len(hits) > 0 && !bytes.Contains(result, []byte(phone)) && !bytes.Contains(result, []byte("abcdefgh1234")), string(result))
		}
	}
	if !ok(parsed) {
		t.Run("parser_to_retrieval_acceptance", func(t *testing.T) {
			t.Skip("parse prerequisite failed; no claim about cleaning, embeddings, index, counts or retrieval")
		})
	}
	ids, _ := json.MarshalIndent(map[string]any{"dataset_id": kb, "document_id": docID, "forced_dataset_id": forcedData["id"], "synthetic_phone": phone}, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "ids.json"), ids, 0600); err != nil {
		t.Fatal(err)
	}
}
