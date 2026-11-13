package chunk

import (
	"context"
	"fmt"

	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/engine/types"
	"ragflow/internal/entity"
	"ragflow/internal/entity/models"
	"ragflow/internal/sensitive"
	"ragflow/internal/server"
	"ragflow/internal/service"
	"ragflow/internal/utility"
	"strings"
)

// manualSecurity spans only an already validated manual write. Its pending
// marker keeps an ambiguous index/DB outcome from exposing an invented count.
type manualSecurity struct {
	doc       *entity.Document
	processor *sensitive.Processor
	result    sensitive.Result
	operation string
	first     bool
}

func (s *ChunkService) prepareSensitiveChunk(ctx context.Context, doc *entity.Document, kb *entity.Knowledgebase, chunkID string, fields map[string]any) (map[string]any, *manualSecurity, error) {
	if !doc.SecurityProcessingEnabled {
		return fields, nil, nil
	}
	first := chunkID == "" && doc.Type == "virtual" && (doc.Location == nil || *doc.Location == "") && !doc.SecurityProcessed && doc.SecurityFailureReason == ""
	if !doc.SecurityProcessed && !first {
		return nil, nil, sensitive.Failure("SP_NOT_PROCESSED")
	}
	p := server.GetSensitiveProcessor()
	if err := p.Check(ctx); err != nil {
		return nil, nil, err
	}
	ctx = p.Engine.WithBudget(ctx)
	clean, result, err := cleanManualFields(ctx, p.Engine, fields)
	if err != nil {
		return nil, nil, err
	}
	// Validate the resulting document, not just a short replacement fragment.
	source, effective := result.SourceCharacters, result.EffectiveCharacters
	index := service.IndexName(kb.TenantID)
	exists, err := s.docEngine.ChunkStoreExists(ctx, index, kb.ID)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		for offset := 0; ; {
			page, err := s.docEngine.Search(ctx, &types.SearchRequest{
				IndexNames: []string{index}, KbIDs: []string{kb.ID}, Offset: offset, Limit: 256, IncludeUnavailable: true,
				OrderBy: (&types.OrderByExpr{}).Asc("chunk_order_int"),
				Filter:  map[string]any{"doc_id": doc.ID, "exists": "doc_type_kwd", "must_not": map[string]any{"exists": "compile_kwd"}},
			})
			if err != nil {
				return nil, nil, err
			}
			if page == nil {
				return nil, nil, sensitive.Failure("SP_RESULT_SAVE_FAILED")
			}
			if first && page.Total != 0 {
				return nil, nil, sensitive.Failure("SP_NOT_PROCESSED")
			}
			if err := p.Engine.ScanChunks(ctx, page.Chunks); err != nil {
				round, _ := doc.SecurityProcessingRecord["pipeline_log_id"].(string)
				if saveErr := s.documentDAO.FailSecurity(ctx, dao.DB, doc.ID, round, sensitive.Reason(err)); saveErr != nil {
					return nil, nil, saveErr
				}
				return nil, nil, err
			}
			for _, row := range page.Chunks {
				if row["id"] == chunkID {
					continue
				}
				text, _ := row["content_with_weight"].(string)
				n := p.Engine.Characters(text)
				source += n
				effective += n
			}
			offset += len(page.Chunks)
			if int64(offset) >= page.Total {
				break
			}
			if len(page.Chunks) == 0 {
				return nil, nil, sensitive.Failure("SP_RESULT_SAVE_FAILED")
			}
		}
	}
	if err = sensitive.ValidateContent(source, effective, p.MinimumCharacters, p.MinimumRatio); err != nil {
		return nil, nil, err
	}
	return clean, &manualSecurity{doc: doc, processor: p, result: result, first: first, operation: common.GenerateToken()}, nil
}

// Count only body replacements; names, keywords, questions and tags are cleaned
// but are not additional source-text replacement events.
func cleanManualFields(ctx context.Context, e *sensitive.Engine, fields map[string]any) (map[string]any, sensitive.Result, error) {
	text, ok := fields["content_with_weight"].(string)
	if !ok {
		return nil, sensitive.Result{}, sensitive.Failure("SP_STRUCTURE_INVALID")
	}
	result, err := e.Clean(ctx, text)
	if err != nil {
		return nil, result, err
	}
	aux := make(map[string]any, len(fields))
	for key, value := range fields {
		if key != "content_with_weight" {
			aux[key] = value
		}
	}
	value, _, err := e.CleanValue(ctx, aux)
	if err != nil {
		return nil, result, err
	}
	clean := value.(map[string]any)
	clean["content_with_weight"] = result.Text
	if err = e.ScanChunks(ctx, []map[string]any{clean}); err != nil {
		return nil, result, err
	}
	return clean, result, nil
}

func (m *manualSecurity) begin(ctx context.Context, chunk map[string]any) error {
	if m == nil {
		return nil
	}
	if err := m.processor.Engine.ScanChunks(ctx, []map[string]any{chunk}); err != nil {
		return err
	}
	return dao.NewDocumentDAO().BeginManualSecurity(ctx, dao.DB, m.doc.ID, m.operation, m.processor.Engine.Version, m.result, m.first)
}

func (m *manualSecurity) finish(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return dao.NewDocumentDAO().FinishSecurityCount(context.WithoutCancel(ctx), dao.DB, m.doc.ID, m.operation, true)
}

func (s *ChunkService) embedManualChunk(ctx context.Context, kb *entity.Knowledgebase, name, text string, questions any) ([]float64, error) {
	model, err := s.getEmbeddingModel(ctx, kb.TenantID, kb.EmbdID)
	if err != nil {
		return nil, err
	}
	if q := filterTrimmedStrings(utility.ConvertToStringSlice(questions)); len(q) > 0 {
		text = strings.Join(q, "\n")
	}
	embeddings, err := model.Embed(ctx, models.EmbedRequest{Texts: []string{name, text}}, &models.EmbeddingConfig{Dimension: 0}, nil)
	if err != nil {
		return nil, err
	}
	if len(embeddings) != 2 {
		return nil, fmt.Errorf("unexpected embedding count: %d", len(embeddings))
	}
	return mergeChunkEmbeddings(embeddings[0].Embedding, embeddings[1].Embedding)
}
