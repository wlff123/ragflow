package sensitive

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Model and storage calls can leave regexp2's timeout clock idle between scans.
// Each small scan must get a fresh deadline when matching resumes.
func TestSensitiveRegexAfterIdle(t *testing.T) {
	e := testEngine(t)
	text := strings.Repeat("Routine operational guidance remains searchable. ", 20)
	if err := e.Scan(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	until := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(until) {
		if err := e.Scan(context.Background(), text); err != nil {
			t.Fatalf("short scan after idle failed: %v", err)
		}
	}
}
