package sensitive

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	f, err := os.Open("../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := Load(f, 100*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRequirementRules(t *testing.T) {
	e := testEngine(t)
	cases := []struct{ input, name, want string }{
		{"password = \"abcdefgh1234\"", "密钥类", "password = \"[敏感信息已移除：密钥类]\""},
		{"110101199003074321", "身份证", ""},
		{"13812345678", "手机号", ""},
		{"6222021234567890123", "银行卡", ""},
		{"LTAI" + strings.Repeat("a", 16), "阿里云 AccessKey ID", ""},
		{"AKID" + strings.Repeat("a", 32), "腾讯云 SecretId", ""},
		{"ALTAK-" + strings.Repeat("a", 21), "百度云 AccessKey ID", ""},
		{"JDC_" + strings.Repeat("A", 28), "京东云 AccessKey ID", ""},
		{"AKLT" + strings.Repeat("a", 20), "金山云 AccessKey ID", ""},
		{"AIza" + strings.Repeat("a", 35), "Google Cloud API Key", ""},
		{"ya29." + strings.Repeat("a", 30), "Google OAuth Access Token", ""},
		{"AKIA" + strings.Repeat("A", 16), "AWS API Key", ""},
		{"amzn.mws.12345678-abcd-abcd-abcd-123456789abc", "AWS MWS Key", ""},
		{"github_pat_" + strings.Repeat("a", 40), "GitHub Personal Access Token（Fine-grained）", ""},
		{"ghp_" + strings.Repeat("a", 36), "GitHub Personal Access Token（Classic）", ""},
		{"gho_" + strings.Repeat("a", 36), "GitHub OAuth 2.0 Access Token", ""},
		{"ghu_" + strings.Repeat("a", 36), "GitHub User-to-Server Access Token", ""},
		{"ghs_" + strings.Repeat("a", 36), "GitHub Server-to-Server Access Token", ""},
		{"ghr_" + strings.Repeat("a", 36), "GitHub Refresh Token", ""},
		{"postgres://reader:abcdefgh@localhost:5432/db", "数据库密码", ""},
		{"-----BEGIN RSA PRIVATE KEY-----\nYWJjZGVm\n-----END RSA PRIVATE KEY-----", "私钥/证书", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = PlaceholderPrefix + tt.name + "]"
			}
			r, err := e.Clean(context.Background(), tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if r.Text != want || r.Count != 1 {
				t.Fatalf("got %q count=%d; want %q count=1", r.Text, r.Count, want)
			}
			again, err := e.Clean(context.Background(), r.Text)
			if err != nil || again.Text != r.Text || again.Count != 0 {
				t.Fatalf("not idempotent: %+v %v", again, err)
			}
		})
	}
}

func TestRuneOffsetsMergeAndBoundaries(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	r, err := e.Clean(ctx, "中文😀号码：13812345678，13912345678。正文保留")
	if err != nil || r.Text != "中文😀号码：[敏感信息已移除：手机号]。正文保留" || r.Count != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = e.Clean(ctx, "13812345678|13912345678")
	if err != nil || r.Count != 2 || !strings.Contains(r.Text, "]|[") {
		t.Fatalf("table boundary lost: %+v %v", r, err)
	}
	for _, text := range []string{"| 13812345678 | 13912345678 |", "13812345678\n13912345678", "13812345678\t13912345678"} {
		r, err = e.Clean(ctx, text)
		if err != nil || r.Count != 2 {
			t.Fatalf("cell or line boundary merged %q: %+v %v", text, r, err)
		}
	}
	r, err = e.Clean(ctx, "x13812345678y")
	if err != nil || r.Count != 0 {
		t.Fatalf("ASCII boundary changed: %+v %v", r, err)
	}
	r, err = e.Clean(ctx, "password=\""+strings.Repeat("a", 160)+"\"")
	if err != nil || r.Text != "password=\"[敏感信息已移除：密钥类]\"" {
		t.Fatalf("long value remains: %+v %v", r, err)
	}
}

func TestPEMLongTruncatedAndEscaped(t *testing.T) {
	e := testEngine(t)
	for _, body := range []string{
		"-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("YQ==", 6000) + "\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\\nYQ==\\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\nYQ==\nProc-Type: 4,ENCRYPTED\ntruncated",
	} {
		r, err := e.Clean(context.Background(), body)
		if err != nil || r.Text != "[敏感信息已移除：私钥/证书]" || r.Count != 1 {
			t.Fatalf("PEM handling count=%d err=%v", r.Count, err)
		}
	}
	r, err := e.Clean(context.Background(), "-----BEGIN PRIVATE KEY-----\nYQ==\n后续正文保留。")
	if err != nil || r.Text != "[敏感信息已移除：私钥/证书]后续正文保留。" || r.Count != 1 {
		t.Fatalf("unclosed PEM removed trailing text: %+v %v", r, err)
	}
}

func TestStructuredSemanticValues(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	r, err := e.CleanJSON(ctx, `{"password":"abc\u0064efgh1234","phone":13812345678,"description":"保留业务描述"}`)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if json.Unmarshal([]byte(r.Text), &got) != nil {
		t.Fatal("invalid JSON")
	}
	if got["password"] != "[敏感信息已移除：密钥类]" || got["phone"] != "[敏感信息已移除：手机号]" || r.Count != 2 {
		t.Fatalf("%+v", r)
	}
	if r, err = e.CleanJSON(ctx, `{"note":"a<b&c"}`); err != nil || r.Text != `{"note":"a<b&c"}` {
		t.Fatalf("JSON text escaped: %+v %v", r, err)
	}
	if v, n, err := e.CleanValue(ctx, map[string]any{"phone": float64(13812345678)}); err != nil || n != 1 || v.(map[string]any)["phone"] != "[敏感信息已移除：手机号]" {
		t.Fatalf("float value missed: %v %d %v", v, n, err)
	}
	if err := e.ScanChunks(ctx, []map[string]any{{"id": "1234567890123456", "mom_id": "6543210987654321", "content_with_weight": "正文"}}); err != nil {
		t.Fatalf("system chunk IDs scanned as business text: %v", err)
	}
	for _, bad := range []string{`{"x":1,"x":2}`, `{"13812345678":1,"13912345678":2}`, `{"x":1} {"y":2}`} {
		if _, err := e.CleanJSON(ctx, bad); Reason(err) != "SP_STRUCTURE_INVALID" {
			t.Fatalf("must reject %q: %v", bad, err)
		}
	}
	r, err = e.CleanYAML(ctx, "password: abcdefgh1234\nphone: 13812345678\nflag: true\n")
	if err != nil || r.Count != 2 || !strings.Contains(r.Text, "flag: true") {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"enabled":null}`, `{"enabled":"true"}`, `{"enabled":true,"enabled":false}`, `{"enabled":true,"extra":false}`} {
		if _, err := ResolveEnabled(json.RawMessage(raw), DatasetConfig{}); Reason(err) != "SP_CONFIG_INVALID" {
			t.Fatalf("accepted %s: %v", raw, err)
		}
	}
	if _, err := ResolveEnabled(json.RawMessage(`{"enabled":false}`), DatasetConfig{true, true}); Reason(err) != "SP_ENFORCED" {
		t.Fatal(err)
	}
	if _, err := DecodeDatasetConfig(json.RawMessage(`{"enforced":true}`), DatasetConfig{}); Reason(err) != "SP_CONFIG_INVALID" {
		t.Fatal(err)
	}
	if on, err := ResolveEnabled(nil, DatasetConfig{true, false}); err != nil || !on {
		t.Fatalf("%v %v", on, err)
	}
}

func TestFailClosedAndContentThreshold(t *testing.T) {
	e := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Clean(ctx, "safe"); err == nil {
		t.Fatal("cancellation ignored")
	}
	if err := e.Scan(context.Background(), "13812345678"); Reason(err) != "SP_RESCAN_HIT" {
		t.Fatal(err)
	}
	if ValidateContent(1000, 20, 20, .05) == nil || ValidateContent(20, 0, 20, .05) == nil {
		t.Fatal("threshold ignored")
	}
	if err := ValidateContent(100, 20, 20, .05); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(strings.NewReader("catalog_version: bad\nrules: []"), time.Second, time.Second); Reason(err) != "SP_RULES_LOAD_FAILED" {
		t.Fatal(err)
	}
}

func TestCrossItemValues(t *testing.T) {
	e := testEngine(t)
	parts, result, err := e.CleanSegments(context.Background(), []string{"前文13812", "345", "678后文"})
	if err != nil || result.Count != 1 || parts[0] != "前文[敏感信息已移除：手机号]" || parts[1] != "" || parts[2] != "后文" {
		t.Fatalf("%q %+v %v", parts, result, err)
	}
}

func TestSharedDocumentBudgetCannotBeRenewed(t *testing.T) {
	e := testEngine(t)
	ctx := context.WithValue(context.Background(), budgetKey{}, &documentBudget{remaining: -time.Second})
	ctx = e.WithBudget(ctx)
	cases := map[string]func() error{
		"text":     func() error { _, err := e.Clean(ctx, "normal text"); return err },
		"scan":     func() error { return e.Scan(ctx, "normal text") },
		"segments": func() error { _, _, err := e.CleanSegments(ctx, []string{"normal", "text"}); return err },
		"json":     func() error { _, err := e.CleanJSON(ctx, `{"text":"normal"}`); return err },
		"yaml":     func() error { _, err := e.CleanYAML(ctx, "text: normal"); return err },
		"value":    func() error { _, _, err := e.CleanValue(ctx, map[string]any{"text": "normal"}); return err },
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); Reason(err) != "SP_REGEX_TIMEOUT" {
				t.Fatalf("budget renewed: %v", err)
			}
		})
	}
	independent := e.WithBudget(context.Background())
	if err := e.Scan(independent, "normal text"); err != nil {
		t.Fatal(err)
	}
}
