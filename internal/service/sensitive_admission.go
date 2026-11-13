package service

import (
	"context"
	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/sensitive"
	"ragflow/internal/server"
)

// ValidateSensitiveDocument runs before scheduling and before destructive reparse preparation.
func ValidateSensitiveDocument(ctx context.Context, doc *entity.Document) error {
	if !doc.SecurityProcessingEnabled {
		return nil
	}
	if doc.SecurityFailureReason == "SP_UPLOAD_FAILED" {
		return sensitive.Failure("SP_UPLOAD_FAILED")
	}
	p := server.GetSensitiveProcessor()
	if err := p.Check(ctx); err != nil {
		return err
	}
	selection := CurrentSelection(doc.ParserID, doc.PipelineID)
	isPipeline, parserID, pipelineID := selection.Effective()
	if err := ValidateSensitivePipeline(ctx, isPipeline, parserID, pipelineID, doc.PipelineVersionID, doc.ParserConfig); err != nil {
		return err
	}
	if doc.Name == nil {
		return sensitive.Failure("SP_CONFIG_INVALID")
	}
	if err := p.Engine.Scan(ctx, *doc.Name); err != nil {
		return err
	}
	if doc.Type == "virtual" {
		return nil
	}
	if doc.Location == nil {
		return sensitive.Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	exists, err := p.Originals.Exists(ctx, *doc.Location)
	if err != nil {
		return err
	}
	if !exists {
		return sensitive.Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return nil
}

// ValidateSensitivePipeline checks the selected version with the caller's effective parameters.
func ValidateSensitivePipeline(ctx context.Context, isPipeline bool, parserID string, pipelineID, versionID *string, config map[string]any) error {
	dsl, err := LoadPipelineDSL(ctx, isPipeline, parserID, pipelineID, versionID)
	if err != nil {
		return sensitive.Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	return sensitive.ValidatePipeline(dsl, config)
}

// ValidateOrdinaryImport rejects routes that do not isolate and clean originals.
func ValidateOrdinaryImport(kb *entity.Knowledgebase, doc *entity.Document) error {
	if (kb != nil && (kb.SecurityProcessingDefault || kb.SecurityProcessingEnforced)) || (doc != nil && doc.SecurityProcessingEnabled) {
		return sensitive.Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	return nil
}

// DeleteSensitiveOriginal must succeed before removing the document's locator.
// It intentionally does not require the rule engine to be available for cleanup.
func DeleteSensitiveOriginal(ctx context.Context, doc *entity.Document) error {
	if !doc.SecurityProcessingEnabled || doc.Location == nil || *doc.Location == "" {
		return nil
	}
	p := server.GetSensitiveProcessor()
	if p == nil || p.Originals == nil {
		return sensitive.Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	return p.Originals.Delete(ctx, *doc.Location)
}

// readableDocumentChunks keeps only chunks whose document exists and may be
// read (sensitive processing disabled or confirmed), plus dataset compilation
// chunks, which retrieval also keeps. Direct chunk-ID reads use it because they
// bypass retrieval's document pruning; a failed lookup drops everything.
func readableDocumentChunks(ctx context.Context, chunks []map[string]interface{}) []map[string]interface{} {
	ids := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		if id, ok := chunk["doc_id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	docs, err := dao.NewDocumentDAO().GetByIDs(ctx, dao.DB, ids)
	if err != nil {
		return nil
	}
	readable := make(map[string]bool, len(docs))
	for _, doc := range docs {
		readable[doc.ID] = doc.SecurityReadable()
	}
	out := chunks[:0]
	for _, chunk := range chunks {
		docID, _ := chunk["doc_id"].(string)
		if readable[docID] || common.IsDatasetCompilationChunk(chunk) {
			out = append(out, chunk)
		}
	}
	return out
}
