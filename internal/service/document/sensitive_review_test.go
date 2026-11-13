package document

import (
	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"testing"
)

func TestSyncRejectsSensitiveImportsBeforeStorage(t *testing.T) {
	for _, mode := range []string{"default", "enforced", "existing", "unchanged"} {
		t.Run(mode, func(t *testing.T) {
			existing := mode == "existing" || mode == "unchanged"
			svc, db, store, input := setupSyncDocumentTest(t, existing)
			if existing {
				if err := db.Model(&entity.Document{}).Where("id = ?", input.DocumentID).Update("security_processing_enabled", true).Error; err != nil {
					t.Fatal(err)
				}
				if mode == "unchanged" {
					input.SourceDocument.Fingerprint = "old-hash"
				}
			} else {
				field := "security_processing_default"
				if mode == "enforced" {
					field = "security_processing_enforced"
				}
				if err := db.Model(&entity.Knowledgebase{}).Where("id = ?", "kb-sync").Update(field, true).Error; err != nil {
					t.Fatal(err)
				}
			}
			writes := 0
			store.afterPut = func() { writes++ }
			if _, err := svc.Upsert(t.Context(), input); err == nil {
				t.Fatal("sensitive import accepted")
			}
			if writes != 0 {
				t.Fatal("raw blob written before rejection")
			}
			var count int64
			db.Model(&entity.Document{}).Count(&count)
			want := int64(0)
			if existing {
				want = 1
			}
			if count != want {
				t.Fatalf("document count=%d", count)
			}
		})
	}
}

func TestLinkRejectsSensitiveTargetsBeforeReplacing(t *testing.T) {
	for _, field := range []string{"security_processing_default", "security_processing_enforced"} {
		t.Run(field, func(t *testing.T) {
			svc, db, _, input := setupSyncDocumentTest(t, true)
			insertTestKB(t, "kb-target", "tenant-1", 0, 0, 0)
			if err := db.Model(&entity.Knowledgebase{}).Where("id = ?", "kb-target").Update(field, true).Error; err != nil {
				t.Fatal(err)
			}
			mappings, err := dao.NewFile2DocumentDAO().GetByDocumentID(t.Context(), db, input.DocumentID)
			if err != nil || len(mappings) != 1 {
				t.Fatalf("mappings=%v err=%v", mappings, err)
			}
			links := &File2DocumentService{fileDAO: dao.NewFileDAO(), file2DocumentDAO: dao.NewFile2DocumentDAO(), kbDAO: dao.NewKnowledgebaseDAO(), documentDAO: dao.NewDocumentDAO(), documentSvc: svc}
			if err := links.convertFiles(t.Context(), []string{*mappings[0].FileID}, []string{"kb-target"}, "replace"); err == nil {
				t.Fatal("sensitive link accepted")
			}
			if _, err := svc.documentDAO.GetByID(t.Context(), db, input.DocumentID); err != nil {
				t.Fatal("existing document removed", err)
			}
		})
	}
}

func TestSensitiveDeleteFailureKeepsLocatorAndCounters(t *testing.T) {
	svc, db, _, input := setupSyncDocumentTest(t, true)
	doc, err := svc.documentDAO.GetByID(t.Context(), db, input.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	doc.SecurityProcessingEnabled = true
	if err := db.Model(doc).Update("security_processing_enabled", true).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.deleteDocRecordWithCounters(t.Context(), doc, doc.KbID); err == nil {
		t.Fatal("unavailable private store accepted")
	}
	kept, err := svc.documentDAO.GetByID(t.Context(), db, doc.ID)
	if err != nil || kept.Location == nil || *kept.Location != *doc.Location {
		t.Fatalf("locator lost: %v", err)
	}
	kb, err := svc.kbDAO.GetByID(t.Context(), db, doc.KbID)
	if err != nil || kb.DocNum != 1 {
		t.Fatalf("counter changed: %+v %v", kb, err)
	}
}
