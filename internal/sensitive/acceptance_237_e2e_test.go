//go:build e2e

package sensitive_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
)

type acceptance237 struct {
	t                *testing.T
	base, token, out string
	client           *http.Client
	seq              int
}

func object237(v any) map[string]any   { m, _ := v.(map[string]any); return m }
func success237(v map[string]any) bool { return v["code"] == float64(0) }
func (a *acceptance237) request(method, path, ctype string, body io.Reader, save bool) map[string]any {
	a.t.Helper()
	req, err := http.NewRequest(method, a.base+"/api/v1"+path, body)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Authorization", a.token)
	req.Header.Set("Content-Type", ctype)
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(raw, &result)
	if save {
		a.seq++
		b, _ := json.MarshalIndent(map[string]any{"method": method, "path": path, "status": resp.StatusCode, "body": string(raw)}, "", "  ")
		if err := os.WriteFile(filepath.Join(a.out, fmt.Sprintf("matrix-http-%03d.json", a.seq)), b, 0600); err != nil {
			a.t.Fatal(err)
		}
	}
	return result
}
func (a *acceptance237) call(method, path string, body any) map[string]any {
	b, _ := json.Marshal(body)
	return a.request(method, path, "application/json", bytes.NewReader(b), true)
}
func (a *acceptance237) upload(kb, name string, body []byte, config string) map[string]any {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	p, err := w.CreateFormFile("file", name)
	if err != nil {
		a.t.Fatal(err)
	}
	_, _ = p.Write(body)
	if config != "" {
		_ = w.WriteField("security_config", config)
	}
	_ = w.Close()
	return a.request("POST", "/datasets/"+kb+"/documents", w.FormDataContentType(), &buf, true)
}
func (a *acceptance237) parse(kb, id string) map[string]any {
	a.t.Helper()
	start := a.call("POST", "/datasets/"+kb+"/documents/parse", map[string]any{"document_ids": []string{id}})
	if !success237(start) || object237(start["data"])["success_count"] != float64(1) {
		a.t.Fatalf("parse rejected: %v", start)
	}
	return a.waitParsed(kb, id)
}
func (a *acceptance237) waitParsed(kb, id string) map[string]any {
	a.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		res := a.call("GET", "/datasets/"+kb+"/documents", nil)
		rows, _ := object237(res["data"])["docs"].([]any)
		for _, row := range rows {
			d := object237(row)
			if d["id"] == id {
				if d["ingestion_status"] == "COMPLETED" || d["ingestion_status"] == "FAILED" || d["ingestion_status"] == "CANCELED" {
					return d
				}
			}
		}
		time.Sleep(time.Second)
	}
	a.t.Fatal("parse timeout")
	return nil
}
func uploaded237(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	rows, _ := v["data"].([]any)
	if !success237(v) || len(rows) != 1 {
		t.Fatalf("upload failed: %v", v)
	}
	return object237(rows[0])
}

// This test forwards every embedding request to the real deployed model. The
// observer records only aggregate safety checks, never request bodies or hashes.
func TestSensitive237RequirementMatrix(t *testing.T) {
	base := os.Getenv("RAGFLOW_ACCEPTANCE_URL")
	upstream := os.Getenv("RAGFLOW_ACCEPTANCE_EMBEDDING_URL")
	if base == "" || upstream == "" {
		t.Skip("real API and embedding endpoints required")
	}
	out := os.Getenv("RAGFLOW_ACCEPTANCE_OUTPUT")
	if out == "" {
		t.Fatal("evidence directory required")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	a := &acceptance237{t: t, base: strings.TrimRight(base, "/"), out: out, client: &http.Client{Timeout: 60 * time.Second}}
	const phone = "13812345678"
	const secret = "abcdefgh1234"
	const prose = "This document describes routine operational procedures and technical guidance that must remain searchable after sensitive information is removed. "
	samples := []struct{ name, value string }{
		{"密钥类", "password=" + secret}, {"身份证", "11010519491231002X"}, {"手机号", phone}, {"银行卡", "4111111111111111"},
		{"阿里云 AccessKey ID", "LTAI" + strings.Repeat("a", 16)}, {"腾讯云 SecretId", "AKID" + strings.Repeat("a", 32)},
		{"百度云 AccessKey ID", "ALTAK-" + strings.Repeat("a", 21)}, {"京东云 AccessKey ID", "JDC_" + strings.Repeat("A", 28)},
		{"金山云 AccessKey ID", "AKLT" + strings.Repeat("a", 20)}, {"Google Cloud API Key", "AIza" + strings.Repeat("a", 35)},
		{"Google OAuth Access Token", "ya29." + strings.Repeat("a", 30)}, {"AWS API Key", "AKIA" + strings.Repeat("A", 16)},
		{"AWS MWS Key", "amzn.mws.12345678-abcd-abcd-abcd-123456789abc"}, {"GitHub Personal Access Token（Fine-grained）", "github_pat_" + strings.Repeat("a", 40)},
		{"GitHub Personal Access Token（Classic）", "ghp_" + strings.Repeat("a", 36)}, {"GitHub OAuth 2.0 Access Token", "gho_" + strings.Repeat("a", 36)},
		{"GitHub User-to-Server Access Token", "ghu_" + strings.Repeat("a", 36)}, {"GitHub Server-to-Server Access Token", "ghs_" + strings.Repeat("a", 36)},
		{"GitHub Refresh Token", "ghr_" + strings.Repeat("a", 36)}, {"数据库密码", "postgres://reader:abcdefgh@localhost:5432/db"},
	}
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var mu sync.Mutex
	calls, leaks, placeholders := 0, 0, 0
	observer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", 500)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(data))
		var payload any
		_ = json.Unmarshal(data, &payload)
		decoded, _ := json.Marshal(payload)
		if strings.Contains(r.URL.Path, "embedding") {
			mu.Lock()
			calls++
			unsafe := bytes.Contains(decoded, []byte(secret))
			for _, s := range samples {
				if bytes.Contains(decoded, []byte(s.value)) {
					unsafe = true
					break
				}
			}
			if unsafe {
				leaks++
			}
			if bytes.Contains(decoded, []byte("[敏感信息已移除：")) {
				placeholders++
			}
			mu.Unlock()
		}
		proxy.ServeHTTP(w, r)
	}))
	defer observer.Close()
	account := map[string]any{"email": fmt.Sprintf("sensitive237-%d@example.invalid", time.Now().UnixNano()), "password": "ValidationOnly!2026", "nickname": "237 acceptance"}
	b, _ := json.Marshal(account)
	registered := a.request("POST", "/users", "application/json", bytes.NewReader(b), false)
	if !success237(registered) {
		t.Fatalf("register: %v", registered)
	}
	req, _ := http.NewRequest("POST", a.base+"/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	a.token = resp.Header.Get("Authorization")
	resp.Body.Close()
	if a.token == "" {
		t.Fatal("login token missing")
	}
	provider := "/providers/OpenAI-API-Compatible/instances/e2e237"
	if added := a.call("PUT", "/providers", map[string]any{"provider_name": "OpenAI-API-Compatible"}); !success237(added) {
		t.Fatalf("provider setup: %v", added)
	}
	created := a.call("POST", "/providers/OpenAI-API-Compatible/instances", map[string]any{"instance_name": "e2e237", "api_key": "test-only", "base_url": observer.URL + "/v1", "model_info": []any{map[string]any{"model_name": "bge-m3", "model_type": []string{"embedding"}, "max_tokens": 8192}}})
	if !success237(created) {
		t.Fatalf("real model registration: %v", created)
	}
	listed := a.call("GET", provider+"/models", nil)
	models, _ := listed["data"].([]any)
	modelID := ""
	for _, row := range models {
		m := object237(row)
		if m["name"] == "bge-m3" {
			modelID, _ = m["id"].(string)
		}
	}
	if modelID == "" {
		t.Fatalf("embedding model absent: %v", listed)
	}
	ds := a.call("POST", "/datasets", map[string]any{"name": "237 real embedding acceptance", "parse_type": 1, "parser_id": "general", "embedding_model": modelID})
	if !success237(ds) {
		t.Fatalf("dataset: %v", ds)
	}
	kb, _ := object237(ds["data"])["id"].(string)
	ids := map[string]any{"dataset_id": kb, "model_id": modelID, "documents": map[string]string{}}
	defer func() {
		b, _ := json.MarshalIndent(ids, "", "  ")
		_ = os.WriteFile(filepath.Join(out, "matrix-ids.json"), b, 0600)
	}()
	run := func(t *testing.T, name string, content []byte, count int, values []string) (string, string) {
		t.Helper()
		a.t = t
		doc := uploaded237(t, a.upload(kb, name, content, ""))
		id := doc["id"].(string)
		ids["documents"].(map[string]string)[name] = id
		state := a.parse(kb, id)
		if state["ingestion_status"] != "COMPLETED" {
			t.Fatalf("terminal state=%v reason=%v progress=%v", state["ingestion_status"], state["security_failure_reason"], state["progress_msg"])
		}
		if state["security_processed"] != true || state["sensitive_replacement_count"] != float64(count) {
			t.Errorf("security result processed=%v count=%v want=%d", state["security_processed"], state["sensitive_replacement_count"], count)
		}
		res := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		rows, _ := object237(res["data"])["chunks"].([]any)
		if !success237(res) || len(rows) == 0 {
			t.Fatalf("chunks missing: %v", res)
		}
		var text strings.Builder
		for _, r := range rows {
			m := object237(r)
			fmt.Fprintln(&text, m["content"])
		}
		clean := text.String()
		all, _ := json.Marshal(res)
		for _, v := range values {
			if bytes.Contains(all, []byte(v)) {
				t.Errorf("raw synthetic value remains")
			}
		}
		return id, clean
	}
	t.Run("all_20_rules_real_embedding", func(t *testing.T) {
		var input strings.Builder
		input.WriteString(prose)
		for i, s := range samples {
			fmt.Fprintf(&input, "\nCase %d: %s\n%s", i+1, s.value, prose)
		}
		values := []string{secret}
		for _, s := range samples {
			values = append(values, s.value)
		}
		_, clean := run(t, "all-rules.txt", []byte(input.String()), 20, values)
		for _, s := range samples {
			if !strings.Contains(clean, "[敏感信息已移除："+s.name+"]") {
				t.Errorf("missing placeholder %s", s.name)
			}
		}
	})
	t.Run("credential_lists_real_embedding", func(t *testing.T) {
		payload, _ := json.Marshal(map[string]any{"description": strings.Repeat(prose, 4), "password": []any{"abcdefgh1234", []string{"ijklmnop5678"}}})
		_, clean := run(t, "credential-lists.json", payload, 2, []string{"abcdefgh1234", "ijklmnop5678"})
		if strings.Count(clean, "[敏感信息已移除：密钥类]") < 2 {
			t.Fatal("credential list placeholders missing")
		}
	})
	t.Run("private_original_delete_lifecycle", func(t *testing.T) {
		a.t = t
		runOriginalDeleteLifecycle237(t, a, modelID, prose)
	})
	var retryID string
	t.Run("merge_overlap_pem_existing_placeholder", func(t *testing.T) {
		retryID, _ = run(t, "overlap.txt", []byte(prose+"\n11010519491231002X\n"+prose+"\n13812345678，13912345678\n"+prose+"\n-----BEGIN RSA PRIVATE KEY-----\nYWJjZGVm\n-----END RSA PRIVATE KEY-----\n[敏感信息已移除：手机号]"), 3, []string{phone, "13912345678", "11010519491231002X", "YWJjZGVm"})
	})
	if retryID != "" {
		t.Run("reparse_does_not_accumulate_count", func(t *testing.T) {
			a.t = t
			started := a.call("POST", "/documents/ingest", map[string]any{"doc_ids": []string{retryID}, "run": "1", "delete": true})
			if !success237(started) {
				t.Fatalf("reparse rejected: %v", started)
			}
			state := a.waitParsed(kb, retryID)
			if state["security_processed"] != true || state["sensitive_replacement_count"] != float64(3) {
				t.Fatalf("retry count=%v processed=%v", state["sensitive_replacement_count"], state["security_processed"])
			}
		})
	}
	t.Run("already_cleaned_idempotent", func(t *testing.T) { run(t, "cleaned.txt", []byte(prose+"[敏感信息已移除：手机号]"), 0, nil) })
	t.Run("unicode_rune_offsets", func(t *testing.T) {
		_, clean := run(t, "unicode.txt", []byte(prose+"中文😀联系电话："+phone+"。尾部保留"), 1, []string{phone})
		if !strings.Contains(clean, "中文😀联系电话：") || !strings.Contains(clean, "尾部保留") {
			t.Error("Unicode context damaged")
		}
	})
	t.Run("json_preserves_keys_and_escaping", func(t *testing.T) {
		_, clean := run(t, "config.json", []byte(`{"note":"`+prose+`","password":"abc\u0064efgh1234","phone":"`+phone+`"}`), 2, []string{phone, secret})
		if !strings.Contains(clean, "password") || !strings.Contains(clean, "phone") {
			t.Error("JSON field names lost")
		}
	})
	t.Run("yaml_configuration", func(t *testing.T) {
		run(t, "config.yaml", []byte("note: "+prose+"\npassword: "+secret+"\nphone: '"+phone+"'\n"), 2, []string{phone, secret})
	})
	t.Run("go_configuration", func(t *testing.T) {
		_, clean := run(t, "config.go", []byte("package demo\n// "+prose+"\nvar password = \""+secret+"\"\nvar phone = \""+phone+"\"\n"), 2, []string{phone, secret})
		if !strings.Contains(clean, "package demo") {
			t.Error("code structure lost")
		}
	})
	t.Run("markdown_table", func(t *testing.T) {
		_, clean := run(t, "table.md", []byte(prose+"\n| Name | Contact |\n|---|---|\n| Sample | "+phone+" |\n"), 1, []string{phone})
		if !strings.Contains(clean, "Sample") {
			t.Error("table context lost")
		}
	})
	t.Run("xlsx_table", func(t *testing.T) {
		f := excelize.NewFile()
		defer f.Close()
		_ = f.SetCellStr("Sheet1", "A1", "Notes")
		_ = f.SetCellStr("Sheet1", "B1", "Contact")
		_ = f.SetCellStr("Sheet1", "A2", prose)
		_ = f.SetCellStr("Sheet1", "B2", phone)
		buf, err := f.WriteToBuffer()
		if err != nil {
			t.Fatal(err)
		}
		run(t, "table.xlsx", buf.Bytes(), 1, []string{phone})
	})
	t.Run("docx_document", func(t *testing.T) {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		files := map[string]string{
			"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
			"_rels/.rels":         `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
			"word/document.xml":   `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>` + prose + phone + `</w:t></w:r></w:p></w:body></w:document>`}
		for name, body := range files {
			w, err := z.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(w, body)
		}
		_ = z.Close()
		run(t, "guide.docx", buf.Bytes(), 1, []string{phone})
	})
	t.Run("pdf_document", func(t *testing.T) { run(t, "guide.pdf", pdf237(), 1, []string{phone}) })
	t.Run("too_little_valid_content_blocks_index", func(t *testing.T) {
		a.t = t
		doc := uploaded237(t, a.upload(kb, "invalid.txt", []byte(phone), ""))
		id := doc["id"].(string)
		state := a.parse(kb, id)
		if state["security_processed"] != false || state["security_failure_reason"] != "SP_NO_VALID_CONTENT" {
			t.Errorf("unexpected safety state %v", state)
		}
		res := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		if success237(res) {
			t.Error("failed document exposes chunks")
		}
	})
	t.Run("unsupported_zip_rejected", func(t *testing.T) {
		a.t = t
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		w, _ := z.Create("notes.txt")
		_, _ = io.WriteString(w, prose+phone)
		_ = z.Close()
		if success237(a.upload(kb, "code.zip", buf.Bytes(), "")) {
			t.Error("ZIP admitted despite design restriction")
		}
	})
	t.Run("vector_search_returns_safe_nonempty_results", func(t *testing.T) {
		a.t = t
		res := a.call("POST", "/datasets/"+kb+"/search", map[string]any{"question": "technical guidance contact information", "keywords_similarity_weight": 0.1, "similarity_threshold": 0})
		rows, _ := object237(res["data"])["chunks"].([]any)
		if !success237(res) || len(rows) == 0 {
			t.Fatalf("retrieval failed: %v", res)
		}
		data, _ := json.Marshal(res)
		if bytes.Contains(data, []byte(phone)) || bytes.Contains(data, []byte(secret)) {
			t.Error("unsafe retrieval")
		}
	})
	for _, parser := range []string{"book", "laws", "manual", "paper", "one", "qa", "email", "table", "presentation", "picture"} {
		t.Run("builtin_pipeline_"+parser, func(t *testing.T) {
			a.t = t
			originalKB := kb
			defer func() { kb = originalKB }()
			dataset := a.call("POST", "/datasets", map[string]any{"name": "237 pipeline " + parser, "parse_type": 1, "parser_id": parser, "embedding_model": modelID})
			if !success237(dataset) {
				t.Fatalf("pipeline dataset: %v", dataset)
			}
			kb, _ = object237(dataset["data"])["id"].(string)
			name, body := "pipeline-"+parser+".txt", []byte("Chapter 1 Operations\n"+prose+"\nContact: "+phone)
			if parser == "qa" {
				body = []byte("How can I contact support?\t" + prose + phone + "\n")
			}
			if parser == "email" {
				name = "pipeline-email.eml"
				body = []byte("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: Operational guidance\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + prose + phone)
			}
			if parser == "table" {
				f := excelize.NewFile()
				defer f.Close()
				_ = f.SetCellStr("Sheet1", "A1", "Notes")
				_ = f.SetCellStr("Sheet1", "B1", "Contact")
				_ = f.SetCellStr("Sheet1", "A2", prose)
				_ = f.SetCellStr("Sheet1", "B2", phone)
				buf, err := f.WriteToBuffer()
				if err != nil {
					t.Fatal(err)
				}
				name, body = "pipeline-table.xlsx", buf.Bytes()
			}
			if parser == "presentation" {
				name, body = "pipeline-presentation.pptx", presentation237(t)
			}
			if parser == "picture" {
				name, body = "pipeline-picture.png", picture237(t)
			}
			run(t, name, body, 1, []string{phone})
		})
	}
	t.Run("builtin_pipeline_audio", func(t *testing.T) {
		a.t = t
		configFile := os.Getenv("RAGFLOW_ACCEPTANCE_ASR_CONFIG")
		if configFile == "" {
			t.Skip("RAGFLOW_ACCEPTANCE_ASR_CONFIG is required for real ASR")
		}
		var config struct {
			Model            string   `json:"model"`
			BaseURL          string   `json:"base_url"`
			APIKey           string   `json:"api_key"`
			AudioFile        string   `json:"audio_file"`
			ExpectedText     string   `json:"expected_text"`
			ReplacementCount int      `json:"replacement_count"`
			SensitiveValues  []string `json:"sensitive_values"`
		}
		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &config); err != nil {
			t.Fatal("invalid ASR configuration")
		}
		if config.Model == "" || config.BaseURL == "" || config.APIKey == "" || config.ExpectedText == "" {
			t.Fatal("incomplete ASR configuration")
		}
		if !success237(a.call("PUT", "/providers", map[string]any{"provider_name": "Tongyi-Qianwen"})) {
			t.Fatal("ASR provider registration failed")
		}
		payload, _ := json.Marshal(map[string]any{"instance_name": "asr237", "api_key": config.APIKey, "base_url": config.BaseURL, "model_info": []any{map[string]any{"model_name": config.Model, "model_type": []string{"asr"}, "max_tokens": 8192}}})
		// Provider responses may contain credentials; do not persist or print them.
		if !success237(a.request("POST", "/providers/Tongyi-Qianwen/instances", "application/json", bytes.NewReader(payload), false)) {
			t.Fatal("ASR instance registration failed")
		}
		if !success237(a.call("PATCH", "/models/default", map[string]any{"model_provider": "Tongyi-Qianwen", "model_instance": "asr237", "model_name": config.Model, "model_type": "asr"})) {
			t.Fatal("ASR default selection failed")
		}
		originalKB := kb
		defer func() { kb = originalKB }()
		dataset := a.call("POST", "/datasets", map[string]any{"name": "237 real ASR acceptance", "parse_type": 1, "parser_id": "audio", "embedding_model": modelID})
		if !success237(dataset) {
			t.Fatal("audio dataset creation failed")
		}
		kb, _ = object237(dataset["data"])["id"].(string)
		audio, err := os.ReadFile(config.AudioFile)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		beforeCalls, beforeLeaks, beforePlaceholders := calls, leaks, placeholders
		mu.Unlock()
		id, _ := run(t, "pipeline-audio.wav", audio, config.ReplacementCount, config.SensitiveValues)
		mu.Lock()
		afterCalls, afterLeaks, afterPlaceholders := calls, leaks, placeholders
		mu.Unlock()
		if afterCalls <= beforeCalls || afterLeaks != beforeLeaks {
			t.Error("audio embedding missing or contains monitored sensitive values")
		}
		if config.ReplacementCount > 0 && afterPlaceholders <= beforePlaceholders {
			t.Error("audio embedding input has no placeholder")
		}
		observation, _ := json.MarshalIndent(map[string]int{"requests": afterCalls - beforeCalls, "raw_requests": afterLeaks - beforeLeaks, "placeholder_requests": afterPlaceholders - beforePlaceholders}, "", "  ")
		if err := os.WriteFile(filepath.Join(out, "audio-embedding-observation.json"), observation, 0600); err != nil {
			t.Fatal(err)
		}
		chunks := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		encoded, _ := json.Marshal(chunks)
		if !bytes.Contains(encoded, []byte(config.ExpectedText)) {
			t.Error("ASR transcript missing expected historical text")
		}
	})
	// These independent mutation cases deliberately test the current implementation;
	// a failing case is evidence, not an excuse to silently narrow acceptance.
	t.Run("manual_add_cleans_before_embedding", func(t *testing.T) {
		a.t = t
		doc := uploaded237(t, a.upload(kb, "manual-source.txt", []byte(prose), ""))
		id := doc["id"].(string)
		a.parse(kb, id)
		res := a.call("POST", "/datasets/"+kb+"/documents/"+id+"/chunks", map[string]any{"content": prose + phone, "questions": []string{"Contact " + phone + "?"}, "important_keywords": []string{phone}, "tag_kwd": []string{phone}, "tag_feas": map[string]float64{phone: 1}})
		data, _ := json.Marshal(res)
		if !success237(res) || bytes.Contains(data, []byte(phone)) {
			t.Errorf("manual addition not safely processed, code=%v", res["code"])
		}
		got := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		if object237(object237(got["data"])["doc"])["sensitive_replacement_count"] != float64(1) {
			t.Error("manual body count must be 1; auxiliary fields must not inflate it")
		}
	})
	t.Run("empty_document_first_manual_chunk", func(t *testing.T) {
		a.t = t
		res := a.call("POST", "/datasets/"+kb+"/documents?type=empty", map[string]any{"name": "empty-manual", "security_config": map[string]any{"enabled": true}})
		id, _ := object237(res["data"])["id"].(string)
		if !success237(res) || id == "" {
			t.Fatalf("empty upload: %v", res)
		}
		added := a.call("POST", "/datasets/"+kb+"/documents/"+id+"/chunks", map[string]any{"content": prose + phone})
		data, _ := json.Marshal(added)
		if !success237(added) || bytes.Contains(data, []byte(phone)) {
			t.Errorf("empty manual content not cleaned, code=%v", added["code"])
		}
		got := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		if !success237(got) || object237(object237(got["data"])["doc"])["security_processed"] != true {
			t.Error("empty document result not confirmed")
		}
		if object237(object237(got["data"])["doc"])["sensitive_replacement_count"] != float64(1) {
			t.Error("first manual body counted incorrectly")
		}
	})
	t.Run("manual_update_cleans_before_embedding", func(t *testing.T) {
		a.t = t
		id, _ := run(t, "manual-update.txt", []byte(prose), 0, nil)
		listed := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		rows, _ := object237(listed["data"])["chunks"].([]any)
		if len(rows) == 0 {
			t.Fatal("no chunk to update")
		}
		chunkID, _ := object237(rows[0])["id"].(string)
		if chunkID == "" {
			t.Fatalf("chunk id missing: %v", rows[0])
		}
		mu.Lock()
		before := calls
		mu.Unlock()
		updated := a.call("PATCH", "/datasets/"+kb+"/documents/"+id+"/chunks/"+chunkID, map[string]any{"content": prose + phone})
		if !success237(updated) {
			t.Fatalf("update rejected: %v", updated)
		}
		got := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		data, _ := json.Marshal(got)
		if !success237(got) || bytes.Contains(data, []byte(phone)) {
			t.Error("updated chunk exposes raw content")
		}
		mu.Lock()
		after := calls
		mu.Unlock()
		if after <= before {
			t.Error("changed vector input did not re-embed")
		}
		if object237(object237(got["data"])["doc"])["sensitive_replacement_count"] != float64(1) {
			t.Error("update count not recorded")
		}
		rejected := a.call("PATCH", "/datasets/"+kb+"/documents/"+id+"/chunks/"+chunkID, map[string]any{"content": phone})
		if success237(rejected) {
			t.Error("update removed all effective document content")
		}
		unchanged := a.call("GET", "/datasets/"+kb+"/documents/"+id+"/chunks", nil)
		if object237(object237(unchanged["data"])["doc"])["sensitive_replacement_count"] != float64(1) {
			t.Error("rejected update changed count")
		}
	})
	t.Run("manual_write_rejects_unprocessed_source_document", func(t *testing.T) {
		a.t = t
		doc := uploaded237(t, a.upload(kb, "unprocessed-manual.txt", []byte(prose+phone), ""))
		res := a.call("POST", "/datasets/"+kb+"/documents/"+doc["id"].(string)+"/chunks", map[string]any{"content": prose})
		if success237(res) {
			t.Error("manual write bypassed unprocessed source")
		}
	})
	if os.Getenv("RAGFLOW_ACCEPTANCE_FULL") == "1" {
		runExtendedRequirements237(t, a, kb, modelID, prose)
	}
	t.Run("observed_real_embedding_inputs", func(t *testing.T) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.MarshalIndent(map[string]int{"real_embedding_requests": calls, "requests_with_raw_synthetic_values": leaks, "requests_with_placeholders": placeholders}, "", "  ")
		_ = os.WriteFile(filepath.Join(out, "embedding-input-observation.json"), b, 0600)
		if calls == 0 || placeholders == 0 || leaks != 0 {
			t.Errorf("requests=%d placeholders=%d unsafe=%d", calls, placeholders, leaks)
		}
	})
}
