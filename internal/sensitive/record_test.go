package sensitive

import "testing"

func TestRecordSafetyIndependentOfTaskStatus(t *testing.T) {
	r := new(Record)
	if err := r.Begin("run1"); err != nil {
		t.Fatal(err)
	}
	if r.Count() != nil || r.Confirmed {
		t.Fatal("new run is not confirmed")
	}
	if err := r.Confirm("run1", "v1", Result{Count: 3, SourceCharacters: 100, EffectiveCharacters: 80}); err != nil {
		t.Fatal(err)
	}
	if n := r.Count(); n == nil || *n != 3 {
		t.Fatal("confirmed count missing")
	}
	if err := r.Fail("run1", "SP_RESCAN_HIT"); err != nil {
		t.Fatal(err)
	}
	if err := r.Confirm("run1", "v1", Result{Count: 3}); Reason(err) != "SP_RESCAN_HIT" {
		t.Fatal("late success cleared failure")
	}
	if err := r.Begin("run1"); err != nil || r.FailureReason == "" {
		t.Fatal("redelivery reset failure")
	}
	if err := r.Begin("run2"); err != nil || r.FailureReason != "" {
		t.Fatal("new run did not reset")
	}
	if err := r.Confirm("run1", "v1", Result{Count: 3}); err == nil {
		t.Fatal("old run accepted")
	}
}

func TestPendingOperationsDoNotLoseCounts(t *testing.T) {
	r := &Record{Round: "run1", Confirmed: true, BaseCount: 3}
	if err := r.Register("a", 2); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("b", 4); err != nil {
		t.Fatal(err)
	}
	if r.Count() != nil {
		t.Fatal("pending count must be unavailable")
	}
	r.Finish("b", true)
	if r.Count() != nil {
		t.Fatal("other pending operation lost")
	}
	r.Finish("a", true)
	r.Finish("a", true)
	if n := r.Count(); n == nil || *n != 9 {
		t.Fatalf("count = %v", n)
	}
	if err := r.Register("c", 7); err != nil {
		t.Fatal(err)
	}
	r.Finish("c", false)
	if n := r.Count(); n == nil || *n != 9 {
		t.Fatal("failed write counted")
	}
}

func TestPendingSurvivesNewParse(t *testing.T) {
	r := &Record{Round: "run1", Confirmed: true, BaseCount: 3}
	if err := r.Register("a", 2); err != nil {
		t.Fatal(err)
	}
	if err := r.Begin("run2"); err != nil {
		t.Fatal(err)
	}
	if err := r.Confirm("run2", "v1", Result{Count: 8}); err != nil {
		t.Fatal(err)
	}
	r.Finish("a", true)
	if r.Count() != nil || r.ManualCount != 0 || !r.Confirmed {
		t.Fatal("late operation must not count or clear safety")
	}
}

func TestDuplicateRunDisagreementMakesCountUnknown(t *testing.T) {
	r := &Record{Round: "run1"}
	if err := r.Confirm("run1", "v1", Result{Count: 2}); err != nil {
		t.Fatal(err)
	}
	if err := r.Confirm("run1", "v1", Result{Count: 3}); err != nil {
		t.Fatal(err)
	}
	if r.Count() != nil || !r.Confirmed {
		t.Fatal("must retain safety but hide uncertain count")
	}
}
