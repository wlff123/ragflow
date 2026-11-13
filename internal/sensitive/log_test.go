package sensitive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	"ragflow/internal/common"
)

func TestRuleLogCleaningEntrypoints(t *testing.T) {
	t.Setenv(common.EnvLLMDebug, "true")
	e := testEngine(t)
	oldLogger, oldSugar := common.Logger, common.Sugar
	t.Cleanup(func() { common.SyncLog(); common.SetLogCleaner(nil); common.Logger, common.Sugar = oldLogger, oldSugar })
	common.SetLogCleaner(e.CleanLogJSON)
	dir := t.TempDir()
	if err := common.InitLogger("debug", common.FileOutput{Path: dir, Filename: "test.log"}, "test"); err != nil {
		t.Fatal(err)
	}
	common.Info("contact 13812345678")
	common.Error("failed", errors.New("contact 13812345678"))
	common.Error("request failed", errors.New(`{"password":["prefixed1234"]}`))
	common.Logger.Error("index failed", zap.Error(errors.New(`bulk failed, body: {"password":["prefixed5678"]}`)))
	common.Sugar.Infof("contact %s", "13812345678")
	common.StdLogger().Print("contact 13812345678")
	snapshot := map[string]any{"value": "original"}
	snapshotLogger := common.Logger.With(zap.Any("snapshot", snapshot))
	snapshot["value"] = "changed-after-with"
	snapshotLogger.Info("snapshot")
	bound := common.Logger.With(zap.String("password", "abcdefgh1234"), zap.Namespace("nested"))
	bound.Info("payload", zap.Any("value", map[string]any{"phone": int64(13812345678), "password": []string{"ijklmnop5678"}}))
	common.Logger.Info("response", zap.String("body", `{"pass\u0077ord":["abcdefgh1234"],"phone":"\u00313812345678"}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "13812345678") {
			t.Error("logging changed the model request")
		}
		_, _ = io.WriteString(w, `{"content":"contact 13812345678","pass\u0077ord":["abcdefgh1234"]}`)
	}))
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader(`{"content":"contact 13812345678"}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := common.GetSchemeSafeHTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !strings.Contains(string(body), "abcdefgh1234") {
		t.Fatal("logging changed the model response")
	}
	common.SyncLog()
	b, err := os.ReadFile(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"13812345678", "abcdefgh1234", "ijklmnop5678", "prefixed1234", "prefixed5678"} {
		if strings.Contains(string(b), raw) {
			t.Fatalf("raw value in log: %s", raw)
		}
	}
	if !strings.Contains(string(b), "敏感信息已移除") {
		t.Fatal("missing replacement")
	}
	if strings.Contains(string(b), "changed-after-with") || !strings.Contains(string(b), "original") {
		t.Fatal("With did not snapshot fields")
	}
	// Cleaning is global but does not charge the current document or change its count.
	ctx, session, err := WithSession(context.Background(), &Processor{Engine: e}, "doc", "run", "guide.txt")
	if err != nil {
		t.Fatal(err)
	}
	if common.CleanLogText("contact 13812345678") == "contact 13812345678" {
		t.Fatal("persisted text not cleaned")
	}
	if session.Result.Count != 0 {
		t.Fatal("log changed document count")
	}
	if _, err := e.Clean(ctx, "normal text"); err != nil {
		t.Fatal(err)
	}
}

func TestLogJSONEmbeddedBodies(t *testing.T) {
	e := testEngine(t)
	common.SetLogCleaner(e.CleanLogJSON)
	t.Cleanup(func() { common.SetLogCleaner(nil) })
	for _, input := range []string{
		`request failed, {"password":["abcdefgh1234"]} trailing text`,
		`body: {"pass\u0077ord":["abcdefgh1234"]} trailing text`,
		"data: {\"password\":[\"abcdefgh1234\"]}\n\ndata: [DONE] trailing text",
		`first: {"password":["abcdefgh1234"]} second: {"password":["abcdefgh1234"]} trailing text`,
		`[warning] body: {"nested":"body: {\"password\":[\"abcdefgh1234\"]}"} trailing text`,
	} {
		got := common.CleanLogText(input)
		if strings.Contains(got, "abcdefgh1234") || !strings.Contains(got, "敏感信息已移除") || !strings.HasSuffix(got, " trailing text") {
			t.Fatalf("incorrect cleaning: %q", got)
		}
	}
	ordinary := "[warning] not JSON {text} [敏感信息已移除：手机号]"
	if got := common.CleanLogText(ordinary); got != ordinary {
		t.Fatalf("changed ordinary text: %q", got)
	}
	if got := common.CleanLogText(`body: {"x":1,"x":2,"password":"abcdefgh1234"}`); got != common.HiddenLogContent {
		t.Fatalf("duplicate keys not hidden: %q", got)
	}
}

func TestLogJSONPreservesNumbersAndContext(t *testing.T) {
	e := testEngine(t)
	common.SetLogCleaner(e.CleanLogJSON)
	t.Cleanup(func() { common.SetLogCleaner(nil) })
	input := map[string]any{"password": []string{"abcdefgh1234"}, "counter": json.Number("12345")}
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.CleanLogJSON(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "abcdefgh1234") || !strings.Contains(string(out), "12345") {
		t.Fatalf("incorrect result: %s", out)
	}
	if got := common.CleanLogText(`{"x":1,"x":2,"password":"abcdefgh1234"}`); got != common.HiddenLogContent {
		t.Fatalf("duplicate keys not hidden: %s", got)
	}
}

func TestRuleLogConcurrentCleaning(t *testing.T) {
	e := testEngine(t)
	common.SetLogCleaner(e.CleanLogJSON)
	t.Cleanup(func() { common.SetLogCleaner(nil) })
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 10 {
				if got := common.CleanLogText("contact 13812345678"); got != "contact [敏感信息已移除：手机号]" {
					t.Errorf("unexpected log result: %q", got)
				}
			}
		})
	}
	workers.Wait()
}
