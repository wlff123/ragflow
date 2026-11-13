package sensitive

import (
	"encoding/json"
	"testing"
)

func TestOutputProofRejectsMutationReplayAndForeignRun(t *testing.T) {
	s := &Session{}
	output := map[string]any{"chunks": []map[string]any{{"text": "cleaned text"}}}
	if err := s.SealOutput(output); err != nil {
		t.Fatal(err)
	}
	foreign := &Session{}
	if err := foreign.RequireOutput(output); Reason(err) != "SP_PRESPLIT_MISSING" {
		t.Fatal("foreign run accepted")
	}
	b, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	var restored map[string]any
	if err := json.Unmarshal(b, &restored); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireOutput(restored); Reason(err) != "SP_PRESPLIT_MISSING" {
		t.Fatal("serialized proof accepted")
	}
	chunks := output["chunks"].([]map[string]any)
	chunks[0]["text"] = "changed text"
	if err := s.RequireOutput(output); Reason(err) != "SP_PRESPLIT_MISSING" {
		t.Fatal("mutation accepted")
	}
	chunks[0]["text"] = "cleaned text"
	output["_elapsed_time"] = 1.0
	// Canvas statePre injects its snapshot after the upstream component seals.
	output["state"] = map[string]any{"Parser:1": map[string]any{"name": "guide.txt"}}
	if err := s.RequireOutput(output); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireOutput(output); Reason(err) != "SP_PRESPLIT_MISSING" {
		t.Fatal("replayed proof accepted")
	}
}
