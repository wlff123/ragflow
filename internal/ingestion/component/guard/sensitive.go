package guard

import (
	"context"

	"ragflow/internal/ingestion/component/schema"
	"ragflow/internal/sensitive"
)

// Finish checks the actual output and preserves safety failures on every exit.
// Callers defer it immediately after accepting the preceding stage's proof.
func Finish(ctx context.Context, session *sensitive.Session, output *map[string]any, err *error) {
	*err = session.Reject(*err)
	if *err == nil {
		if chunks, ok := schema.GetChunks(*output); ok {
			*err = session.Processor.Engine.ScanChunks(ctx, schema.ChunkDocsToMaps(chunks))
		} else {
			*err = sensitive.Failure("SP_STRUCTURE_INVALID")
		}
		if *err == nil {
			*err = session.SealOutput(*output)
		}
	}
	*err = session.Reject(*err)
	if *err != nil {
		*output = nil
	}
}
