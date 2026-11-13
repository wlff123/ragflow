package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/sensitive"
)

func TestValidateSensitivePipelineUsesSelectedVersionAndOverrides(t *testing.T) {
	db := setupServiceTestDB(t)
	if err := db.AutoMigrate(&entity.UserCanvasVersion{}); err != nil {
		t.Fatal(err)
	}
	previous := dao.DB
	dao.DB = db
	t.Cleanup(func() { dao.DB = previous })
	raw, err := LoadPipelineDSL(t.Context(), false, "general", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var dsl entity.JSONMap
	if err := json.Unmarshal(raw, &dsl); err != nil {
		t.Fatal(err)
	}
	canvasID, versionID := "security-canvas", "security-version"
	if err := db.Create(&entity.UserCanvas{ID: canvasID, CanvasCategory: "dataflow_canvas", DSL: entity.JSONMap{}}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&entity.UserCanvasVersion{ID: versionID, UserCanvasID: canvasID, DSL: dsl}).Error; err != nil {
		t.Fatal(err)
	}
	if err := ValidateSensitivePipeline(t.Context(), true, "", &canvasID, &versionID, nil); err != nil {
		t.Fatalf("selected valid version rejected: %v", err)
	}
	overrides := map[string]any{"File": map[string]any{"binary": "unchecked input"}}
	if err := ValidateSensitivePipeline(t.Context(), true, "", &canvasID, &versionID, overrides); sensitive.Reason(err) != "SP_PIPELINE_NOT_ALLOWED" {
		t.Fatalf("unsafe override not rejected: %v", err)
	}
	missing := "missing-version"
	if err := ValidateSensitivePipeline(t.Context(), true, "", &canvasID, &missing, nil); sensitive.Reason(err) != "SP_PIPELINE_NOT_ALLOWED" {
		t.Fatalf("load failure not normalized: %v", err)
	}
}

func TestReadableDocumentChunksAllowsOnlyConfirmedDocuments(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&entity.Document{}); err != nil {
		t.Fatal(err)
	}
	origDB := dao.DB
	dao.DB = db
	t.Cleanup(func() { dao.DB = origDB })
	for _, doc := range []entity.Document{
		{ID: "plain", KbID: "kb", ParserConfig: entity.JSONMap{}},
		{ID: "processed", KbID: "kb", ParserConfig: entity.JSONMap{}, SecurityProcessingEnabled: true, SecurityProcessed: true},
		{ID: "pending", KbID: "kb", ParserConfig: entity.JSONMap{}, SecurityProcessingEnabled: true},
	} {
		if err = db.Create(&doc).Error; err != nil {
			t.Fatal(err)
		}
	}
	got := readableDocumentChunks(context.Background(), []map[string]interface{}{
		{"id": "1", "doc_id": "plain"},
		{"id": "2", "doc_id": "processed"},
		{"id": "3", "doc_id": "pending"},
		{"id": "4", "doc_id": "deleted"},
		{"id": "5"},
		{"id": "6", "doc_id": "kb", "kb_id": "kb", "scope_kwd": "dataset", "compile_kwd": "summary"},
	})
	var ids []string
	for _, chunk := range got {
		ids = append(ids, chunk["id"].(string))
	}
	if len(ids) != 3 || ids[0] != "1" || ids[1] != "2" || ids[2] != "6" {
		t.Fatalf("readable chunks = %v", ids)
	}
}
