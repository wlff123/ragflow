package task

import (
	"context"
	"time"

	"ragflow/internal/common"
	enginetypes "ragflow/internal/engine/types"
	"ragflow/internal/sensitive"
	"ragflow/internal/service"
)

// persistSensitiveMetadata checks and writes the complete metadata once. The
// later bookkeeping step must not re-merge unchecked stored fields.
func (s *PipelineExecutor) persistSensitiveMetadata(ctx context.Context, session *sensitive.Session, incoming map[string]any) error {
	eng := s.deps.Engine
	if eng == nil {
		return sensitive.Failure("SP_UNSUPPORTED_DEPLOYMENT")
	}
	tenant, doc := s.taskCtx.Tenant.ID, s.taskCtx.Doc
	exists, err := eng.MetadataStoreExists(ctx, tenant)
	if err != nil {
		return err
	}
	var existing map[string]any
	if exists {
		result, err := eng.SearchMetadata(ctx, &enginetypes.SearchMetadataRequest{
			TenantID: tenant, Limit: 1,
			Filter: map[string]any{"kb_id": doc.KbID, "id": []string{doc.ID}},
		})
		if err != nil {
			return err
		}
		if result == nil {
			return sensitive.Failure("SP_STRUCTURE_INVALID")
		}
		if len(result.MetadataRecords) > 0 {
			existing, err = service.ExtractMetaFields(result.MetadataRecords[0])
			if err != nil {
				return sensitive.Failure("SP_STRUCTURE_INVALID")
			}
		}
	}
	merged := common.MergeDocumentMetadata(existing, incoming)
	config, enabled := builtInMetadataFromParserConfig(doc.ParserConfig)
	if enabled {
		merged = common.MergeDocumentMetadata(merged, common.BuiltInDocumentMetadata(session.Name, time.Now().Format("2006-01-02 15:04:05"), config))
	}
	if err := session.Processor.Engine.ScanValue(ctx, merged); err != nil {
		return err
	}
	if !exists {
		if err := eng.CreateMetadataStore(ctx, tenant); err != nil {
			return err
		}
	}
	return eng.UpdateMetadata(ctx, doc.ID, doc.KbID, merged, tenant)
}
