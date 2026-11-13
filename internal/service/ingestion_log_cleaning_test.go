package service

import (
	"os"
	"strings"
	"testing"
	"time"

	"ragflow/internal/common"
	"ragflow/internal/dao"
	"ragflow/internal/entity"
	"ragflow/internal/sensitive"
)

func TestRuleCleaningBeforeTaskLogPersistence(t *testing.T) {
	f, err := os.Open("../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	common.SetLogCleaner(e.CleanLogJSON)
	t.Cleanup(func() { common.SetLogCleaner(nil) })
	db := setupServiceTestDB(t)
	if err := db.AutoMigrate(&entity.IngestionTaskLog{}, &entity.PipelineOperationLog{}); err != nil {
		t.Fatal(err)
	}
	svc := NewIngestionTaskService()
	if err := svc.insertEventOnDB(t.Context(), db, ingestionEventLifecycle, "run", "task", "contact 13812345678", 0, "password=abcdefgh1234"); err != nil {
		t.Fatal(err)
	}
	var event entity.IngestionTaskLog
	if err := db.First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(event.Component, "13812345678") || strings.Contains(event.Message, "abcdefgh1234") {
		t.Fatal("raw task log persisted")
	}
	if !strings.Contains(event.Message, "敏感信息已移除") {
		t.Fatal("missing task log replacement")
	}
	run, err := dao.NewPipelineOperationLogDAO().CreateOpenLog(t.Context(), db, dao.OpenLogInput{DocumentID: "doc", KbID: "kb", RunCount: 1, DocumentName: "13812345678.txt", PipelineTitle: "password=abcdefgh1234"})
	if err != nil {
		t.Fatal(err)
	}
	var stored entity.PipelineOperationLog
	if err := db.First(&stored, "id = ?", run.ID).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.DocumentName, "13812345678") || stored.PipelineTitle == nil || strings.Contains(*stored.PipelineTitle, "abcdefgh1234") {
		t.Fatal("raw pipeline snapshot persisted")
	}
}
