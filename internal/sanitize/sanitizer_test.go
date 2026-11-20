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

package sanitize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// All sample values below are synthetic.

func mustDefault(t *testing.T) *Sanitizer {
	t.Helper()
	s, err := loadDefault(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load builtin rules: %v", err)
	}
	return s
}

func sanitize(t *testing.T, s *Sanitizer, text string) Result {
	t.Helper()
	r, err := s.Sanitize(context.Background(), text)
	if err != nil {
		t.Fatalf("Sanitize(%q): %v", text, err)
	}
	return r
}

func TestSanitize_EachRule(t *testing.T) {
	alnum := func(n int) string { return strings.Repeat("Ab1", n)[:n] }
	hexUpper := strings.Repeat("0A1B2C3D", 4)[:28]
	cases := []struct {
		id, name, in, want string
	}{
		{"SECRET_KV", "密钥类", "password=abcd1234efgh", "password=[敏感信息已移除：密钥类]"},
		{"CN_ID_CARD", "身份证", "身份证号110101199003071234。", "身份证号[敏感信息已移除：身份证]。"},
		{"CN_MOBILE", "手机号", "联系电话13800138000请回电", "联系电话[敏感信息已移除：手机号]请回电"},
		{"BANK_CARD", "银行卡", "卡号 6222020200112233445 已绑定", "卡号 [敏感信息已移除：银行卡] 已绑定"},
		{"ALIYUN_AK", "阿里云 AccessKey ID", "ak LTAI" + alnum(16) + " end", "ak [敏感信息已移除：阿里云 AccessKey ID] end"},
		{"TENCENT_SECRET_ID", "腾讯云 SecretId", "id AKID" + alnum(32) + " end", "id [敏感信息已移除：腾讯云 SecretId] end"},
		{"BAIDU_AK", "百度云 AccessKey ID", "ak ALTAK" + alnum(21) + " end", "ak [敏感信息已移除：百度云 AccessKey ID] end"},
		{"JDCLOUD_AK", "京东云 AccessKey ID", "ak JDC_" + hexUpper + " end", "ak [敏感信息已移除：京东云 AccessKey ID] end"},
		{"KSYUN_AK", "金山云 AccessKey ID", "ak AKLT" + alnum(20) + " end", "ak [敏感信息已移除：金山云 AccessKey ID] end"},
		{"GCP_API_KEY", "Google Cloud API Key", "key AIza" + alnum(35) + " end", "key [敏感信息已移除：Google Cloud API Key] end"},
		{"GOOGLE_OAUTH_TOKEN", "Google OAuth Access Token", "tk ya29." + alnum(30) + " end", "tk [敏感信息已移除：Google OAuth Access Token] end"},
		{"AWS_API_KEY", "AWS API Key", "ak AKIA" + strings.Repeat("Z9", 8) + " end", "ak [敏感信息已移除：AWS API Key] end"},
		{"AWS_MWS_KEY", "AWS MWS Key", "mws amzn.mws.0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f end", "mws [敏感信息已移除：AWS MWS Key] end"},
		{"GITHUB_PAT_FINE", "GitHub Personal Access Token（Fine-grained）", "t github_pat_" + alnum(40) + " end", "t [敏感信息已移除：GitHub Personal Access Token（Fine-grained）] end"},
		{"GITHUB_PAT", "GitHub Personal Access Token（Classic）", "t ghp_" + alnum(36) + " end", "t [敏感信息已移除：GitHub Personal Access Token（Classic）] end"},
		{"GITHUB_OAUTH", "GitHub OAuth 2.0 Access Token", "t gho_" + alnum(36) + " end", "t [敏感信息已移除：GitHub OAuth 2.0 Access Token] end"},
		{"GITHUB_U2S", "GitHub User-to-Server Access Token", "t ghu_" + alnum(36) + " end", "t [敏感信息已移除：GitHub User-to-Server Access Token] end"},
		{"GITHUB_S2S", "GitHub Server-to-Server Access Token", "t ghs_" + alnum(36) + " end", "t [敏感信息已移除：GitHub Server-to-Server Access Token] end"},
		{"GITHUB_REFRESH", "GitHub Refresh Token", "t ghr_" + alnum(36) + " end", "t [敏感信息已移除：GitHub Refresh Token] end"},
		{"DB_PASSWORD", "数据库密码", "dsn mysql://root:Passw0rd@db.local:3306/app end", "dsn [敏感信息已移除：数据库密码] end"},
	}
	s := mustDefault(t)
	if info := s.Rules(); info.Source != SourceBuiltin || info.Version == "" {
		t.Fatalf("rule catalog: %+v", info)
	}
	if len(s.rules) != len(cases) {
		t.Fatalf("catalog has %d rules, want %d", len(s.rules), len(cases))
	}
	for i, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			if rule := s.rules[i]; rule.ID != c.id || rule.Name != c.name {
				t.Fatalf("rule %d = %s (%s), want %s (%s)", i, rule.ID, rule.Name, c.id, c.name)
			}
			r := sanitize(t, s, c.in)
			if r.Text != c.want || r.Count != 1 {
				t.Fatalf("got %q (count %d), want %q (count 1)", r.Text, r.Count, c.want)
			}
		})
	}
}

func TestSanitize_NegativeSamples(t *testing.T) {
	s := mustDefault(t)
	for _, in := range []string{
		"普通文本，没有敏感信息。",
		"订单号 A13800138000B",         // mobile embedded in an alphanumeric token
		"电话 1380013800",             // 10 digits
		"短数字 123456789012",          // 12 digits: below the bank card length
		"password=short",            // value shorter than 8
		"ghp_tooShort",              // GitHub token too short
		"mysql://db.local:3306/app", // no credentials
	} {
		r := sanitize(t, s, in)
		if r.Count != 0 || r.Text != in || r.RuleHits != nil {
			t.Errorf("%q: got %q count %d hits %v", in, r.Text, r.Count, r.RuleHits)
		}
	}
}

func TestSanitize_OverlapCountsOnce(t *testing.T) {
	// An 18-digit id card number is also 13-19 digits (bank card); the higher
	// priority id card rule names the single placeholder.
	r := sanitize(t, mustDefault(t), "证件 110101199003071234")
	if r.Text != "证件 [敏感信息已移除：身份证]" || r.Count != 1 || r.RuleHits["CN_ID_CARD"] != 1 {
		t.Fatalf("got %q count %d hits %v", r.Text, r.Count, r.RuleHits)
	}
}

func TestSanitize_OverlapPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
		secondPriority      int
		winner              string
	}{
		{"containment before priority", "abcd", "bc", 2, "A"},
		{"priority before length", "abc", "cd", 2, "B"},
		{"length before order", "ab", "bcd", 1, "B"},
		{"catalog order breaks tie", "bcd", "abc", 1, "A"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newSanitizer(&catalog{Rules: []rule{
				{ID: "A", Name: "A", Scope: scopeFull, Priority: 1, Pattern: tc.first},
				{ID: "B", Name: "B", Scope: scopeFull, Priority: tc.secondPriority, Pattern: tc.second},
			}}, SourceExternal)
			if err != nil {
				t.Fatal(err)
			}
			r := sanitize(t, s, "abcd")
			if r.Text != placeholder(tc.winner) || r.Count != 1 || r.RuleHits[tc.winner] != 1 {
				t.Fatalf("overlap result: %+v", r)
			}
		})
	}
}

func TestSanitize_AdjacentSameRuleMerged(t *testing.T) {
	s := mustDefault(t)
	r := sanitize(t, s, "电话：13800138000、13900139000, 13700137000")
	if r.Text != "电话：[敏感信息已移除：手机号]" || r.Count != 1 {
		t.Fatalf("merged: got %q count %d", r.Text, r.Count)
	}
	// Line breaks and table separators keep hits apart.
	r = sanitize(t, s, "13800138000\n13900139000")
	if r.Count != 2 || strings.Count(r.Text, "[敏感信息已移除：手机号]") != 2 {
		t.Fatalf("newline: got %q count %d", r.Text, r.Count)
	}
	r = sanitize(t, s, "| 13800138000 | 13900139000 |")
	if r.Text != "| [敏感信息已移除：手机号] | [敏感信息已移除：手机号] |" || r.Count != 2 {
		t.Fatalf("table: got %q count %d", r.Text, r.Count)
	}
	// Different rules are never merged.
	r = sanitize(t, s, "13800138000 6222020200112233445")
	if r.Count != 2 {
		t.Fatalf("different rules: got %q count %d", r.Text, r.Count)
	}
}

func TestSanitize_KeyValueKeepsKeyAndSyntax(t *testing.T) {
	s := mustDefault(t)
	cases := map[string]string{
		"password: abcd1234efgh":            "password: [敏感信息已移除：密钥类]",
		"api_key = 'abcd1234efgh'":          "api_key = '[敏感信息已移除：密钥类]'",
		`token="abcd1234efgh"`:              `token="[敏感信息已移除：密钥类]"`,
		"db:\n  passwd: abcd1234efgh\n":     "db:\n  passwd: [敏感信息已移除：密钥类]\n",
		"client_secret=>abcd1234efgh, next": "client_secret=>[敏感信息已移除：密钥类], next",
	}
	for in, want := range cases {
		if r := sanitize(t, s, in); r.Text != want || r.Count != 1 {
			t.Errorf("%q: got %q count %d, want %q", in, r.Text, r.Count, want)
		}
	}
	// The YAML stays parseable after replacement.
	r := sanitize(t, s, "db:\n  passwd: abcd1234efgh\n  host: local\n")
	var v map[string]any
	if err := yaml.Unmarshal([]byte(r.Text), &v); err != nil {
		t.Fatalf("yaml after sanitize: %v\n%s", err, r.Text)
	}
}

func TestSanitize_JSONStaysValid(t *testing.T) {
	s := mustDefault(t)
	in := `{"name":"张三","phone":13800138000,"password":"abcd1234efgh","contacts":["13900139000"],"note":"<a&b>","n":42}`
	r := sanitize(t, s, in)
	var got map[string]any
	if err := json.Unmarshal([]byte(r.Text), &got); err != nil {
		t.Fatalf("invalid JSON after sanitize: %v\n%s", err, r.Text)
	}
	if got["phone"] != "[敏感信息已移除：手机号]" ||
		got["password"] != "[敏感信息已移除：密钥类]" ||
		got["contacts"].([]any)[0] != "[敏感信息已移除：手机号]" ||
		got["name"] != "张三" || got["note"] != "<a&b>" || got["n"] != float64(42) {
		t.Fatalf("unexpected values: %v", got)
	}
	if r.Count != 3 {
		t.Fatalf("count = %d, want 3", r.Count)
	}
	// Key order and untouched bytes are preserved.
	if !strings.HasPrefix(r.Text, `{"name":"张三","phone":"[`) || !strings.HasSuffix(r.Text, `,"note":"<a&b>","n":42}`) {
		t.Fatalf("layout changed: %s", r.Text)
	}

	arr := sanitize(t, s, "[\n  {\"user_id\": \"u1234567890\"},\n  \"plain\"\n]")
	if err := json.Unmarshal([]byte(arr.Text), new(any)); err != nil || arr.Count != 1 {
		t.Fatalf("array: %v count %d\n%s", err, arr.Count, arr.Text)
	}
}

// TestSanitize_JSONDecodedView checks that a JSON document is matched on its
// decoded values: escapes do not hide a value, array elements keep the key of
// the field holding the array, and a match spanning several tokens neither
// rewrites JSON syntax nor counts as a hit.
func TestSanitize_JSONDecodedView(t *testing.T) {
	s := mustDefault(t)
	cases := []struct {
		name, in string
		want     map[string]any
		count    int
	}{
		{"escaped slash", `{"dsn":"mysql:\/\/root:Passw0rd@db.local"}`, map[string]any{"dsn": "[敏感信息已移除：数据库密码]"}, 1},
		{"unicode escape", `{"note":"\u0031\u0033800138000"}`, map[string]any{"note": "[敏感信息已移除：手机号]"}, 1},
		{"array under key", `{"password":["abcd1234efgh"]}`, map[string]any{"password": []any{"[敏感信息已移除：密钥类]"}}, 1},
		{"cross-token text", `{"url":"mysql://u:pw","email":"a@b.com"}`, map[string]any{"url": "mysql://u:pw", "email": "a@b.com"}, 0},
	}
	for _, c := range cases {
		r := sanitize(t, s, c.in)
		var got map[string]any
		if err := json.Unmarshal([]byte(r.Text), &got); err != nil {
			t.Errorf("%s: invalid JSON: %v\n%s", c.name, err, r.Text)
			continue
		}
		if !reflect.DeepEqual(got, c.want) || r.Count != c.count {
			t.Errorf("%s: got %v count %d, want %v count %d", c.name, got, r.Count, c.want, c.count)
		}
	}
}

func TestSanitize_JSONWithOuterWhitespace(t *testing.T) {
	const left, right = "\u00a0 ", "\n\u3000"
	input := left + `{"note":"\u0031\u0033800138000"}` + right
	want := left + `{"note":"[敏感信息已移除：手机号]"}` + right
	r, err := mustDefault(t).SanitizeField(t.Context(), "body", input)
	if err != nil || r.Text != want || r.Count != 1 {
		t.Fatalf("text=%q count=%d err=%v", r.Text, r.Count, err)
	}
}

func TestSanitize_Idempotent(t *testing.T) {
	s := mustDefault(t)
	for _, in := range []string{
		"电话 13800138000，password=abcd1234efgh，卡 6222020200112233445",
		`{"phone":13800138000,"token":"abcd1234efgh"}`,
	} {
		first := sanitize(t, s, in)
		second := sanitize(t, s, first.Text)
		if second.Count != 0 || second.Text != first.Text {
			t.Fatalf("not idempotent: %q -> %q (count %d)", first.Text, second.Text, second.Count)
		}
	}
	// A bracket with an unknown rule name is not a standard placeholder.
	r := sanitize(t, s, "[敏感信息已移除：未知13800138000]")
	if r.Count != 1 || r.Text != "[敏感信息已移除：未知[敏感信息已移除：手机号]]" {
		t.Fatalf("unknown placeholder name should not mask: %q", r.Text)
	}
}

func TestSanitize_RejectsResidual(t *testing.T) {
	// Replacing FIRST makes SECOND eligible only on the second pass.
	s, err := newSanitizer(&catalog{Rules: []rule{{
		ID: "TEST", Name: "测试", Scope: scopeFull, Pattern: `FIRST|(?<!FIRST)SECOND`,
	}}}, SourceExternal)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, value string }{
		{"", "FIRSTSECOND"}, {"note", "FIRSTSECOND"}, {"", `{"note":"FIRSTSECOND"}`},
	} {
		_, err := s.SanitizeField(t.Context(), tc.key, tc.value)
		if !errors.Is(err, ErrResidual) || err.Error() != "SANITIZE_RESIDUAL_DETECTED" {
			t.Errorf("residual for %q: %v", tc.value, err)
		}
	}
}

func TestSanitizeField(t *testing.T) {
	s := mustDefault(t)
	ctx := context.Background()
	cases := []struct{ key, value, want string }{
		// The key gives the key/value rule its context.
		{"password", "abcd1234efgh", "[敏感信息已移除：密钥类]"},
		{"api_key", "abcd1234efgh, rotated", "[敏感信息已移除：密钥类], rotated"},
		// A hit inside the key is not written into the value.
		{"13800138000", "普通内容", "普通内容"},
		// Without key context the same value is ordinary text.
		{"note", "abcd1234efgh", "abcd1234efgh"},
		{"", "电话 13800138000", "电话 [敏感信息已移除：手机号]"},
		{"body", `{"phone":13800138000}`, `{"phone":"[敏感信息已移除：手机号]"}`},
	}
	for _, c := range cases {
		r, err := s.SanitizeField(ctx, c.key, c.value)
		if err != nil || r.Text != c.want {
			t.Errorf("SanitizeField(%q, %q) = %q, %v; want %q", c.key, c.value, r.Text, err, c.want)
		}
	}
	// Idempotent on its own output.
	first, _ := s.SanitizeField(ctx, "password", "abcd1234efgh")
	if again, err := s.SanitizeField(ctx, "password", first.Text); err != nil || again.Count != 0 || again.Text != first.Text {
		t.Fatalf("not idempotent: %+v %v", again, err)
	}
}

func TestSanitize_Context(t *testing.T) {
	s := mustDefault(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sanitize(ctx, "电话 13800138000"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: err = %v", err)
	}
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	if _, err := s.Sanitize(dctx, "电话 13800138000"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("deadline: err = %v", err)
	}
}

func TestSanitize_Concurrent(t *testing.T) {
	s := mustDefault(t)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.Sanitize(context.Background(), "电话 13800138000，token: abcd1234efgh")
			if err == nil && r.Count != 2 {
				err = errors.New(r.Text)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestSanitize_MatcherTimeoutHidesInput(t *testing.T) {
	s := mustDefault(t)
	// Expire this private matcher's deadline without timing a slow regex.
	s.rules[0].re.MatchTimeout = -time.Second
	_, err := s.Sanitize(t.Context(), "password=privateFixtureMarker")
	if !errors.Is(err, ErrTimeout) || err.Error() != "SANITIZE_TIMEOUT" {
		t.Fatalf("matcher timeout: %v", err)
	}
}

// --- rule loading -----------------------------------------------------------

// builtinCatalogForTest returns a mutable copy of the built-in catalog.
func builtinCatalogForTest(t *testing.T) *catalog {
	t.Helper()
	c, err := builtinCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func encodeCatalog(t *testing.T, c *catalog) []byte {
	t.Helper()
	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewFromReader_ExternalOverride(t *testing.T) {
	c := builtinCatalogForTest(t)
	c.Version = "2026.11.19-test"
	for i := range c.Rules {
		if c.Rules[i].ID == "BANK_CARD" {
			// Tighten the bank card rule to 16-19 digits.
			c.Rules[i].Pattern = `(?<![0-9A-Za-z])\d{16,19}(?![0-9A-Za-z])`
		}
	}
	s, err := newFromReader(bytes.NewReader(encodeCatalog(t, c)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if info := s.Rules(); info.Source != SourceExternal || info.Version != "2026.11.19-test" {
		t.Fatalf("info = %+v", info)
	}
	if r := sanitize(t, s, "编号 6222020200112"); r.Count != 0 {
		t.Fatalf("13 digits should no longer match: %q", r.Text)
	}
}

func TestNewFromReader_RejectsInvalidCatalogs(t *testing.T) {
	mutate := map[string]func(c *catalog) []byte{
		"rule removed": func(c *catalog) []byte {
			c.Rules = c.Rules[:ruleCount-1]
			return nil
		},
		"rule added": func(c *catalog) []byte {
			c.Rules = append(c.Rules, rule{ID: "EXTRA", Name: "额外", Scope: scopeFull, Pattern: "x+"})
			return nil
		},
		"rule replaced": func(c *catalog) []byte {
			c.Rules[0].ID = "OTHER"
			return nil
		},
		"display name changed": func(c *catalog) []byte {
			c.Rules[2].Name = "电话"
			return nil
		},
		"scope changed": func(c *catalog) []byte {
			c.Rules[0].Scope = scopeFull
			return nil
		},
		"duplicate id": func(c *catalog) []byte {
			c.Rules[1].ID = c.Rules[0].ID
			return nil
		},
		"invalid regex": func(c *catalog) []byte {
			c.Rules[3].Pattern = `(\d+`
			return nil
		},
		"matches empty": func(c *catalog) []byte {
			c.Rules[3].Pattern = `\d*`
			return nil
		},
		"matches a placeholder": func(c *catalog) []byte {
			c.Rules[3].Pattern = `敏感信息`
			return nil
		},
		"missing version": func(c *catalog) []byte {
			c.Version = ""
			return nil
		},
		"unknown field": func(c *catalog) []byte {
			return []byte("catalog_version: x\nunknown: 1\nrules: []\n")
		},
		"two documents": func(c *catalog) []byte {
			b, _ := yaml.Marshal(c)
			return append(append(b, []byte("---\n")...), b...)
		},
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			c := builtinCatalogForTest(t)
			raw := m(c)
			if raw == nil {
				raw = encodeCatalog(t, c)
			}
			if _, err := newFromReader(bytes.NewReader(raw)); !errors.Is(err, ErrRulesUnavailable) || err.Error() != "SANITIZE_RULES_UNAVAILABLE" {
				t.Fatalf("err = %v, want %v", err, ErrRulesUnavailable)
			}
		})
	}
}

func TestLoadDefault_Sources(t *testing.T) {
	env := func(path string) func(string) string {
		return func(k string) string {
			if k == envRulesPath {
				return path
			}
			return ""
		}
	}

	s, err := loadDefault(env("  "))
	if err != nil || s.Rules().Source != SourceBuiltin {
		t.Fatalf("blank env: %v %+v", err, s)
	}

	dir := t.TempDir()
	good := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(good, encodeCatalog(t, builtinCatalogForTest(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = loadDefault(env(good))
	if err != nil || s.Rules().Source != SourceExternal {
		t.Fatalf("external: %v", err)
	}

	// A missing or invalid external file fails; it never falls back to the
	// built-in rules.
	if _, err := loadDefault(env(filepath.Join(dir, "missing.yaml"))); !errors.Is(err, ErrRulesUnavailable) {
		t.Fatalf("missing file: err = %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("catalog_version: x\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDefault(env(bad)); !errors.Is(err, ErrRulesUnavailable) {
		t.Fatalf("invalid file: err = %v", err)
	}
}

func TestDefault_CachedInstance(t *testing.T) {
	a, errA := Default()
	b, errB := Default()
	if errA != nil || errB != nil || a == nil || a != b {
		t.Fatalf("Default not cached: %v %v", errA, errB)
	}
}

func TestJSONCollisionPreservesMembers(t *testing.T) {
	s := mustDefault(t)
	const mark = "[敏感信息已移除：手机号]"
	const numbered = "[敏感信息已移除：手机号_2]"
	// The unchanged key occurs last; the existing placeholder in the prefix stays put.
	input := `{"before":0,"@-13800138000":"A","@-13900139000":"B","@-#":"keep","child":{"13800138000":1,"13900139000":2}}`
	want := `{"before":0,"@-@":"A","@-[敏感信息已移除：手机号_3]":"B","@-#":"keep","child":{"@":1,"#":2}}`
	expand := strings.NewReplacer("@", mark, "#", numbered)
	r := sanitize(t, s, expand.Replace(input))
	if r.Text != expand.Replace(want) || r.Count != 4 || r.RuleHits["CN_MOBILE"] != 4 {
		t.Fatalf("%+v", r)
	}
	if again := sanitize(t, s, r.Text); again.Count != 0 || again.Text != r.Text {
		t.Fatalf("second pass: %+v", again)
	}
}

func TestHTMLBody(t *testing.T) {
	s := mustDefault(t)
	const phone = "[敏感信息已移除：手机号]"
	for _, tc := range []struct {
		in, want string
		count    int
	}{
		{"<p>mysql://root:pw@db.local/app</p><p>正文</p>", "<p>[敏感信息已移除：数据库密码]</p><p>正文</p>", 1},
		{`<div title="&#49;3800138000">电话 &#49;3800138000</div>`, `<div title="` + phone + `">电话 ` + phone + `</div>`, 2},
		{`<INPUT disabled ConsumerKey = 'abcd1234efgh' title="untouched &amp; OK"/>`, `<INPUT disabled ConsumerKey = '[敏感信息已移除：密钥类]' title="untouched &amp; OK"/>`, 1},
		{`<iframe srcdoc="&lt;p&gt;&#49;3800138000&lt;/p&gt;"></iframe>`, `<iframe srcdoc="&lt;p&gt;` + phone + `&lt;/p&gt;"></iframe>`, 1},
		{`<p>13800</p><p>138000</p>`, `<p>13800</p><p>138000</p>`, 0},
		{`<P data-x='a &amp; b'>普通</P>`, `<P data-x='a &amp; b'>普通</P>`, 0},
	} {
		r, err := s.SanitizeHTML(t.Context(), tc.in)
		if err != nil || r.Text != tc.want || r.Count != tc.count {
			t.Errorf("%s: %+v %v", tc.in, r, err)
		}
		if again, err := s.SanitizeHTML(t.Context(), r.Text); err != nil || again.Count != 0 || again.Text != r.Text {
			t.Errorf("second pass: %+v %v", again, err)
		}
	}
	if _, err := s.SanitizeHTML(t.Context(), "<p>13800<b>138000</b></p>"); !errors.Is(err, ErrResidual) {
		t.Errorf("split number: %v", err)
	}
}

func TestExternalValueSpan(t *testing.T) {
	c := builtinCatalogForTest(t)
	for i := range c.Rules {
		if c.Rules[i].ID == "SECRET_KV" {
			c.Rules[i].Pattern = `password:\s*["']?[A-Za-z.]+["']?`
		}
	}
	s, err := newFromReader(bytes.NewReader(encodeCatalog(t, c)))
	if err != nil {
		t.Fatal(err)
	}
	r := sanitize(t, s, `password: "example.suffix"`)
	if r.Text != `password: "[敏感信息已移除：密钥类]"` || r.Count != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestNumberedPlaceholderLocalToJSONKeys(t *testing.T) {
	c := builtinCatalogForTest(t)
	for i := range c.Rules {
		if c.Rules[i].ID == "BANK_CARD" {
			c.Rules[i].Pattern = "手机号_2"
		}
	}
	s, err := newFromReader(bytes.NewReader(encodeCatalog(t, c)))
	if err != nil {
		t.Fatal(err)
	}
	input := `{"13800138000":"A","13900139000":"B"}`
	want := `{"[敏感信息已移除：手机号]":"A","[敏感信息已移除：手机号_2]":"B"}`
	if r := sanitize(t, s, input); r.Text != want || r.Count != 2 {
		t.Fatal(r)
	}
	if r := sanitize(t, s, want); r.Text != want || r.Count != 0 {
		t.Fatal(r)
	}
	for _, padding := range []string{"", strings.Repeat(" ", 50)} {
		if r := sanitize(t, s, "[敏感信息已移除：手机号_2]"+padding); r.Count != 1 {
			t.Fatal(r)
		}
	}
}
