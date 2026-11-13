package document

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/sensitive"
	"ragflow/internal/service"
)

type uncertainOriginalStore struct {
	sensitive.OriginalStorage
	put       func(context.Context, string) error
	deleteErr error
	objects   map[string]bool
	deletes   int
}

func (s *uncertainOriginalStore) PutOriginal(ctx context.Context, location, _ string, _ []byte) error {
	s.objects[location] = true // The server accepted the bytes before the response failed.
	return s.put(ctx, location)
}
func (s *uncertainOriginalStore) Delete(ctx context.Context, location string) error {
	s.deletes++
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.objects, location)
	return nil
}

func TestSensitiveUploadUncertainPutCleanup(t *testing.T) {
	for _, scenario := range []string{"response_lost", "canceled", "delete_failed", "database_failed", "publish_failed", "success"} {
		t.Run(scenario, func(t *testing.T) {
			db := setupServiceTestDB(t)
			pushServiceDB(t, db)
			kbID, docID := strings.Repeat("a", 32), strings.Repeat("b", 32)
			insertTestKB(t, kbID, "tenant-1", 0, 0, 0)
			svc := testDocumentService(t)
			kb, err := svc.kbDAO.GetByID(t.Context(), db, kbID)
			if err != nil {
				t.Fatal(err)
			}
			folder, err := svc.ensureKBFolder(t.Context(), kb, "tenant-1")
			if err != nil {
				t.Fatal(err)
			}
			doc := &entity.Document{ID: docID, KbID: kbID, Name: sptr("guide.txt"), ParserID: "general", ParserConfig: entity.JSONMap{}, Type: "doc", CreatedBy: "user-1", SecurityProcessingEnabled: true}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &uncertainOriginalStore{objects: map[string]bool{}}
			store.put = func(_ context.Context, location string) error {
				stored, err := svc.documentDAO.GetByID(t.Context(), db, docID)
				if err != nil || stored.Location == nil || *stored.Location != location || stored.SecurityFailureReason != "SP_UPLOAD_FAILED" {
					t.Fatalf("PUT started without durable retry record: %+v %v", stored, err)
				}
				if err := service.ValidateSensitiveDocument(t.Context(), stored); sensitive.Reason(err) != "SP_UPLOAD_FAILED" {
					t.Fatal("unfinished upload admitted", err)
				}
				if scenario == "canceled" {
					cancel()
					return context.Canceled
				}
				if scenario == "success" || scenario == "publish_failed" {
					return nil
				}
				return sensitive.Failure("SP_ORIGINAL_UNAVAILABLE")
			}
			if scenario == "publish_failed" {
				if err := db.Exec("CREATE TRIGGER fail_upload_publish BEFORE UPDATE OF security_failure_reason ON document BEGIN SELECT RAISE(ABORT, 'injected publish failure'); END").Error; err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "delete_failed" {
				store.deleteErr = errors.New("storage offline")
			}
			if scenario == "database_failed" {
				if err := db.Exec("CREATE TRIGGER fail_upload_cleanup BEFORE DELETE ON document BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END").Error; err != nil {
					t.Fatal(err)
				}
			}
			err = svc.saveSensitiveUpload(ctx, store, doc, folder.ID, kb.TenantID, "guide.txt", []byte("synthetic original"))
			if (err == nil) != (scenario == "success") {
				t.Fatalf("upload result: %v", err)
			}
			if scenario == "success" {
				stored, err := svc.documentDAO.GetByID(t.Context(), db, docID)
				if err != nil || stored.SecurityFailureReason != "" || store.deletes != 0 || len(store.objects) != 1 {
					t.Fatal("successful upload not published")
				}
				return
			}
			if store.deletes != 1 {
				t.Fatalf("cleanup attempts=%d", store.deletes)
			}
			if scenario == "delete_failed" || scenario == "database_failed" {
				stored, err := svc.documentDAO.GetByID(t.Context(), db, docID)
				if err != nil || stored.Location == nil || *stored.Location != *doc.Location {
					t.Fatal("retry locator lost", err)
				}
				store.deleteErr = nil
				if scenario == "database_failed" {
					if err := db.Exec("DROP TRIGGER fail_upload_cleanup").Error; err != nil {
						t.Fatal(err)
					}
				}
				if err := testDocumentService(t).cleanupSensitiveUpload(t.Context(), store, stored); err != nil {
					t.Fatal("retry failed", err)
				}
			}
			if len(store.objects) != 0 {
				t.Fatal("orphan original retained")
			}
			var rows int64
			if err := db.Model(&entity.Document{}).Where("id = ?", docID).Count(&rows).Error; err != nil || rows != 0 {
				t.Fatal("document not cleaned", err)
			}
			kb, err = svc.kbDAO.GetByID(t.Context(), db, kbID)
			if err != nil || kb.DocNum != 0 {
				t.Fatal("counter not restored", err)
			}
			mappings, err := dao.NewFile2DocumentDAO().GetByDocumentID(t.Context(), db, docID)
			if err != nil || len(mappings) != 0 {
				t.Fatal("file mapping retained", err)
			}
		})
	}
}
