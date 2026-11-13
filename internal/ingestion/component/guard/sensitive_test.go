package guard

import (
	"context"
	"errors"
	"testing"

	"ragflow/internal/sensitive"
)

func TestFinishPreservesLatchedFailureOnEveryExit(t *testing.T) {
	for _, later := range []error{nil, errors.New("model failed"), context.Canceled} {
		session := &sensitive.Session{}
		session.Reject(sensitive.Failure("SP_STRUCTURE_INVALID"))
		output := map[string]any{"chunks": []any{}}
		err := later
		Finish(context.Background(), session, &output, &err)
		if sensitive.Reason(err) != "SP_STRUCTURE_INVALID" || output != nil {
			t.Fatalf("lost failure: %v, %#v", err, output)
		}
	}
}

func TestFinishPreservesOrdinaryFailure(t *testing.T) {
	session := &sensitive.Session{}
	want := errors.New("model failed")
	err := want
	output := map[string]any{}
	Finish(context.Background(), session, &output, &err)
	if err != want || output != nil {
		t.Fatalf("changed ordinary failure: %v", err)
	}
}
