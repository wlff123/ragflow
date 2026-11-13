package dao

import (
	"context"
	"testing"

	"ragflow/internal/entity"
	"ragflow/internal/sensitive"

	"gorm.io/gorm"
)

func TestManualSecurityFirstWriteAndPendingCount(t *testing.T) {
	db := setupDocumentTestDB(t)
	ctx := context.Background()
	d := NewDocumentDAO()
	for _, kind := range []string{"virtual", "doc"} {
		doc := &entity.Document{ID: kind, Type: kind, KbID: "kb", ParserID: "general", CreatedBy: "user", ParserConfig: entity.JSONMap{}, SecurityProcessingEnabled: true}
		if err := db.Create(doc).Error; err != nil {
			t.Fatal(err)
		}
		err := d.BeginManualSecurity(ctx, db, kind, "op1", "v1", sensitive.Result{Count: 2, SourceCharacters: 100, EffectiveCharacters: 80}, true)
		if kind == "doc" {
			if sensitive.Reason(err) != "SP_NOT_PROCESSED" {
				t.Fatalf("ordinary document admitted: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := d.GetByID(ctx, db, kind)
		if err != nil || !got.SecurityProcessed || got.SensitiveReplacementCount != nil {
			t.Fatal("pending first write must hide count", got, err)
		}
		if err := d.FinishSecurityCount(ctx, db, kind, "op1", true); err != nil {
			t.Fatal(err)
		}
		if err := d.FinishSecurityCount(ctx, db, kind, "op1", true); err != nil {
			t.Fatal(err)
		}
		got, _ = d.GetByID(ctx, db, kind)
		if got.SensitiveReplacementCount == nil || *got.SensitiveReplacementCount != 2 {
			t.Fatal("first write counted incorrectly", got.SensitiveReplacementCount)
		}
		if err := d.BeginManualSecurity(ctx, db, kind, "op2", "v1", sensitive.Result{Count: 1}, false); err != nil {
			t.Fatal(err)
		}
		if err := d.FinishSecurityCount(ctx, db, kind, "op2", true); err != nil {
			t.Fatal(err)
		}
		got, _ = d.GetByID(ctx, db, kind)
		if got.SensitiveReplacementCount == nil || *got.SensitiveReplacementCount != 3 {
			t.Fatal("subsequent write lost count")
		}
	}
}

func TestDocumentSecurityLifecycle(t *testing.T) {
	db := setupDocumentTestDB(t)
	ctx := context.Background()
	d := NewDocumentDAO()
	doc := &entity.Document{ID: "security-doc", KbID: "kb", ParserID: "general", CreatedBy: "user", ParserConfig: entity.JSONMap{}, SecurityProcessingEnabled: true}
	if err := db.Create(doc).Error; err != nil {
		t.Fatal(err)
	}
	begin := func(round string) {
		t.Helper()
		if err := db.Transaction(func(tx *gorm.DB) error {
			locked, err := d.GetByIDForUpdate(ctx, tx, doc.ID)
			if err != nil {
				return err
			}
			return d.BeginSecurityRun(ctx, tx, locked, round)
		}); err != nil {
			t.Fatal(err)
		}
	}
	load := func() *entity.Document {
		t.Helper()
		value, err := d.GetByID(ctx, db, doc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	begin("round1")
	if got := load(); got.SecurityProcessed || got.SensitiveReplacementCount != nil {
		t.Fatal("new run exposed results")
	}
	if err := d.ConfirmSecurity(ctx, db, doc.ID, "round1", "v1", sensitive.Result{Count: 2}); err != nil {
		t.Fatal(err)
	}
	if err := d.BeginManualSecurity(ctx, db, doc.ID, "op1", "v1", sensitive.Result{Count: 3}, false); err != nil {
		t.Fatal(err)
	}
	if got := load(); !got.SecurityProcessed || got.SensitiveReplacementCount != nil {
		t.Fatal("pending result must retain safety and hide count")
	}
	if err := d.FinishSecurityCount(ctx, db, doc.ID, "op1", true); err != nil {
		t.Fatal(err)
	}
	if err := d.FinishSecurityCount(ctx, db, doc.ID, "op1", true); err != nil {
		t.Fatal(err)
	}
	if got := load(); got.SensitiveReplacementCount == nil || *got.SensitiveReplacementCount != 5 {
		t.Fatal("counter not persisted exactly once")
	}
	if err := d.FailSecurity(ctx, db, doc.ID, "round1", "SP_RESCAN_HIT"); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfirmSecurity(ctx, db, doc.ID, "round1", "v1", sensitive.Result{Count: 2}); sensitive.Reason(err) != "SP_RESCAN_HIT" {
		t.Fatal("same-round failure cleared", err)
	}
	begin("round2")
	if err := d.ConfirmSecurity(ctx, db, doc.ID, "round1", "v1", sensitive.Result{Count: 2}); sensitive.Reason(err) != "SP_RESULT_SAVE_FAILED" {
		t.Fatal("stale run accepted", err)
	}
	if got := load(); got.SecurityProcessed || got.SecurityFailureReason != "" || got.SensitiveReplacementCount != nil {
		t.Fatal("new round state incorrect")
	}
}

func TestDocumentSecurityRunRollbackAndOrdinaryDocument(t *testing.T) {
	db := setupDocumentTestDB(t)
	ctx := context.Background()
	d := NewDocumentDAO()
	doc := &entity.Document{ID: "security-doc", KbID: "kb", ParserID: "general", CreatedBy: "user", ParserConfig: entity.JSONMap{}, SecurityProcessingEnabled: true}
	if err := db.Create(doc).Error; err != nil {
		t.Fatal(err)
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := d.BeginSecurityRun(ctx, tx, doc, "rollback"); err != nil {
			return err
		}
		return sensitive.Failure("SP_RESULT_SAVE_FAILED")
	})
	if err == nil {
		t.Fatal("expected rollback")
	}
	got, err := d.GetByID(ctx, db, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SecurityProcessingRecord) != 0 {
		t.Fatal("run result escaped binding transaction")
	}
	ordinary := &entity.Document{ID: "ordinary", KbID: "kb", ParserID: "general", CreatedBy: "user", ParserConfig: entity.JSONMap{}}
	if err := db.Create(ordinary).Error; err != nil {
		t.Fatal(err)
	}
	if err := d.BeginSecurityRun(ctx, db, ordinary, "round"); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetByID(ctx, db, ordinary.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SecurityProcessingEnabled || len(got.SecurityProcessingRecord) != 0 {
		t.Fatal("ordinary document changed")
	}
}
