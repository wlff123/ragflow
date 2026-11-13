package canvas

import (
	"os"
	"strings"
	"testing"
	"time"

	"ragflow/internal/common"
	"ragflow/internal/sensitive"
)

func TestRuleCleaningBeforeRunFailurePersistence(t *testing.T) {
	f, err := os.Open("../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	common.SetLogCleaner(e.CleanLogJSON)
	t.Cleanup(func() { common.SetLogCleaner(nil) })
	tracker, mr := newTestTracker(t, time.Minute)
	if err := tracker.MarkFailed(t.Context(), "run", "password=abcdefgh1234"); err != nil {
		t.Fatal(err)
	}
	value := mr.HGet(runKey("run"), "failure_reason")
	if strings.Contains(value, "abcdefgh1234") || !strings.Contains(value, "敏感信息已移除") {
		t.Fatalf("unsafe Redis reason: %s", value)
	}
}
