package document

import (
	"context"
	"path/filepath"
	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/permission"
	"ragflow/internal/sensitive"
	"ragflow/internal/server"
	"ragflow/internal/service"
	"ragflow/internal/utility"
	"strings"
)

func (s *DocumentService) OpenOriginal(ctx context.Context, datasetID, documentID string) (*sensitive.Original, error) {
	if err := service.CheckDocumentAccess(ctx, documentID, datasetID, permission.OperationRead); err != nil {
		return nil, err
	}
	doc, err := s.documentDAO.GetByDocumentIDAndDatasetID(ctx, dao.DB, documentID, datasetID)
	if err != nil {
		return nil, ErrDocumentNotFound
	}
	if !doc.SecurityProcessingEnabled || doc.Location == nil || *doc.Location == "" {
		return nil, sensitive.Failure("SP_ORIGINAL_UNAVAILABLE")
	}
	p := server.GetSensitiveProcessor()
	if err := p.Check(ctx); err != nil {
		return nil, err
	}
	return p.Originals.OpenOriginal(ctx, *doc.Location)
}

// uploadSensitiveDocument stores originals exclusively in private storage.
// Only the cleaned display name is written to document and file records.
func (s *DocumentService) uploadSensitiveDocument(ctx context.Context, kb *entity.Knowledgebase, userID, folderID, originalName string, blob []byte, config entity.JSONMap, source string) (*entity.Document, error) {
	p := server.GetSensitiveProcessor()
	if err := p.Check(ctx); err != nil {
		return nil, err
	}
	if strings.EqualFold(filepath.Ext(originalName), ".zip") {
		return nil, sensitive.Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	result, err := p.Engine.Clean(ctx, originalName)
	if err != nil {
		return nil, err
	}
	name, err := common.UniqueFileName(result.Text, common.NameLimit255, func(candidate string) (bool, error) {
		return s.documentDAO.NameExistsInKB(ctx, dao.DB, kb.ID, candidate)
	})
	if err != nil {
		return nil, sensitive.Failure("SP_UPLOAD_FAILED")
	}
	filetype := utility.FilenameType(originalName)
	if blob != nil && filetype == utility.FileTypeOTHER {
		return nil, sensitive.Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	selection, parserConfig := resolveDocumentParser(ctx, kb, originalName, filetype, config)
	kind := string(filetype)
	if blob == nil {
		kind = "virtual"
		selection = service.CurrentSelection(kb.ParserID, kb.PipelineID)
		parserConfig = config
	}
	doc := s.newDatasetDocument(kb, userID, name, "", kind, selection, parserConfig, source, int64(len(blob)), nil)
	doc.SecurityProcessingEnabled = true
	isPipeline, parserID, pipelineID := selection.Effective()
	if err := service.ValidateSensitivePipeline(ctx, isPipeline, parserID, pipelineID, doc.PipelineVersionID, doc.ParserConfig); err != nil {
		return nil, err
	}
	if err := s.saveSensitiveUpload(ctx, p.Originals, doc, folderID, kb.TenantID, originalName, blob); err != nil {
		return nil, err
	}
	return doc, nil
}

// Keep the locator durable until either publication or cleanup succeeds. The
// existing document/dataset deletion paths can retry a failed cleanup.
func (s *DocumentService) saveSensitiveUpload(ctx context.Context, originals sensitive.OriginalStorage, doc *entity.Document, folderID, tenantID, originalName string, blob []byte) (err error) {
	unlock := lockDocumentParse(doc.ID)
	defer unlock()
	if blob != nil {
		location, err := sensitive.NewOriginalLocation(doc.KbID, doc.ID)
		if err != nil {
			return err
		}
		doc.Location = &location
	}
	doc.SecurityFailureReason = "SP_UPLOAD_FAILED"
	if err = s.InsertDocument(ctx, doc); err != nil {
		return sensitive.Failure("SP_UPLOAD_FAILED")
	}
	defer func() {
		if err == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupBatchTimeout)
		defer cancel()
		_ = s.cleanupSensitiveUpload(cleanupCtx, originals, doc)
	}()
	if err = s.addFileFromKB(ctx, doc, folderID, tenantID); err != nil {
		return sensitive.Failure("SP_UPLOAD_FAILED")
	}
	if blob != nil {
		if err = originals.PutOriginal(ctx, *doc.Location, originalName, blob); err != nil {
			return err
		}
	}
	if err = s.documentDAO.UpdateByID(ctx, dao.DB, doc.ID, map[string]any{"security_failure_reason": ""}); err != nil {
		return sensitive.Failure("SP_UPLOAD_FAILED")
	}
	doc.SecurityFailureReason = ""
	return nil
}

func (s *DocumentService) cleanupSensitiveUpload(ctx context.Context, originals sensitive.OriginalStorage, doc *entity.Document) error {
	// Never delete the retry record if any cleanup step failed.
	if doc.Location != nil && *doc.Location != "" {
		if err := originals.Delete(ctx, *doc.Location); err != nil {
			return err
		}
	}
	if err := s.cleanupFileReferences(ctx, doc); err != nil {
		return err
	}
	return s.deleteDocRowWithCounters(ctx, doc, doc.KbID)
}
