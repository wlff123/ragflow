package sensitive

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
)

const proofKey = "_sensitive_output"

type outputProof struct {
	digest [sha256.Size]byte
}

type outputGuard struct {
	mu      sync.Mutex
	current *outputProof
	failure error
}

// SealOutput binds the exact output to this in-memory run. The proof has no
// serializable fields: checkpoints, API JSON and another run cannot recreate it.
// Call only after the owning stage has completed its safety checks.
func (s *Session) SealOutput(output map[string]any) error {
	digest, err := outputDigest(output)
	if err != nil {
		return err
	}
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	if s.guard.failure != nil {
		return s.guard.failure
	}
	proof := &outputProof{digest: digest}
	s.guard.current = proof
	output[proofKey] = proof
	return nil
}

// RequireOutput consumes the preceding stage's proof before downstream work.
// A copied marker with changed business data, or a replay, is rejected.
func (s *Session) RequireOutput(input map[string]any) error {
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	proof, ok := input[proofKey].(*outputProof)
	if !ok || proof == nil || proof != s.guard.current {
		return Failure("SP_PRESPLIT_MISSING")
	}
	digest, err := outputDigest(input)
	if err != nil {
		return err
	}
	if digest != proof.digest {
		return Failure("SP_PRESPLIT_MISSING")
	}
	s.guard.current = nil
	return nil
}

func outputDigest(output map[string]any) ([sha256.Size]byte, error) {
	if output == nil {
		return [sha256.Size]byte{}, Failure("SP_PRESPLIT_MISSING")
	}
	data := make(map[string]any, len(output))
	for key, value := range output {
		switch key {
		// Canvas owns these fields. Admitted ingestion stages consume explicit
		// payload fields; the runtime snapshot is not the stage's business input.
		case proofKey, "_created_time", "_elapsed_time", "__cpn_id__", "state":
			continue
		}
		data[key] = value
	}
	b, err := json.Marshal(data)
	if err != nil {
		return [sha256.Size]byte{}, Failure("SP_STRUCTURE_INVALID")
	}
	return sha256.Sum256(b), nil
}

// Reject preserves a latched safety failure even when a later stage
// returns an ordinary error. It must run on every component exit.
func (s *Session) Reject(err error) error {
	s.guard.mu.Lock()
	defer s.guard.mu.Unlock()
	if s.guard.failure == nil && Reason(err) != "" {
		s.guard.failure = err
	}
	if s.guard.failure != nil {
		return s.guard.failure
	}
	return err
}
