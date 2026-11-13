package task

import (
	"context"
	"errors"
	"os"
	"ragflow/internal/dao"
	"ragflow/internal/engine"
	enginetypes "ragflow/internal/engine/types"
	"ragflow/internal/entity"
	"ragflow/internal/sensitive"
	"strings"
	"testing"
	"time"
)

func TestSensitiveIndexBoundary(t *testing.T) {
	for _, test := range []struct {
		name, text string
		mutate     bool
		reason     string
	}{
		{"raw business field", "customer 13812345678", false, "SP_RESCAN_HIT"},
		{"changed output", "safe business text", true, "SP_PRESPLIT_MISSING"},
		{"ordinary index failure", "safe business text", false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := setupPipelineExecutorTestDB(t)
			defer cleanup()
			f, err := os.Open("../../../conf/sensitive_rules.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			e, err := sensitive.Load(f, time.Second, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			doc := entity.Document{ID: strings.Repeat("a", 32), KbID: strings.Repeat("b", 32), Name: strPtr("guide.txt"), SecurityProcessingEnabled: true, ParserConfig: entity.JSONMap{}}
			if err := dao.DB.Create(&doc).Error; err != nil {
				t.Fatal(err)
			}
			if err := dao.NewDocumentDAO().BeginSecurityRun(context.Background(), dao.DB, &doc, "run"); err != nil {
				t.Fatal(err)
			}
			ctx, session, err := sensitive.WithSession(context.Background(), &sensitive.Processor{Engine: e}, doc.ID, "run", *doc.Name)
			if err != nil {
				t.Fatal(err)
			}
			session.Parsed = true
			session.Result = sensitive.Result{Count: 2, SourceCharacters: 80, EffectiveCharacters: 60}
			taskCtx := &TaskContext{Doc: doc, Tenant: entity.Tenant{ID: strings.Repeat("c", 32)}}
			executor := mustNewPipelineExecutor(t, taskCtx, "pipeline", 10)
			executor.deps.Engine = &sensitiveMetadataEngine{}
			calls := 0
			executor.WithInsertFunc(func(context.Context, []map[string]any, string, string) ([]string, error) {
				calls++
				return nil, errors.New("index unavailable")
			})
			executor.WithDeleteChunksFunc(func(context.Context, map[string]any, string, string) (int64, error) { return 0, nil })
			output := map[string]any{"chunks": []map[string]any{{"text": test.text}}, "embedding_token_consumption": 0}
			if err := session.SealOutput(output); err != nil {
				t.Fatal(err)
			}
			if test.mutate {
				output["chunks"].([]map[string]any)[0]["text"] = "replacement"
			}
			_, err = executor.processOutput(ctx, output, time.Now())
			if err == nil || sensitive.Reason(err) != test.reason {
				t.Fatalf("unexpected error: %v", err)
			}
			stored, err := dao.NewDocumentDAO().GetByID(context.Background(), dao.DB, doc.ID)
			if err != nil {
				t.Fatal(err)
			}
			if test.reason != "" {
				if calls != 0 || stored.SecurityProcessed {
					t.Fatal("unsafe output reached index")
				}
			} else if calls != chunkInsertAttempts || !stored.SecurityProcessed || stored.SensitiveReplacementCount == nil || *stored.SensitiveReplacementCount != 2 {
				t.Fatal("index failure erased confirmed safety result")
			}
		})
	}
}

type sensitiveMetadataEngine struct {
	engine.DocEngine
	existing map[string]any
	written  map[string]any
}

func (e *sensitiveMetadataEngine) Search(context.Context, *enginetypes.SearchRequest) (*enginetypes.SearchResult, error) {
	return &enginetypes.SearchResult{}, nil
}
func (e *sensitiveMetadataEngine) MetadataStoreExists(context.Context, string) (bool, error) {
	return true, nil
}
func (e *sensitiveMetadataEngine) SearchMetadata(context.Context, *enginetypes.SearchMetadataRequest) (*enginetypes.SearchMetadataResult, error) {
	return &enginetypes.SearchMetadataResult{MetadataRecords: []map[string]any{{"meta_fields": e.existing}}}, nil
}
func (e *sensitiveMetadataEngine) UpdateMetadata(_ context.Context, _, _ string, value map[string]any, _ string) error {
	e.written = value
	return nil
}

func TestSensitiveMetadataChecksStoredFieldsBeforeWrite(t *testing.T) {
	f, err := os.Open("../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve safe keys", true: "reject retained phone"}[unsafe], func(t *testing.T) {
			doc := entity.Document{ID: "doc", KbID: "kb", Name: strPtr("guide.txt")}
			executor := mustNewPipelineExecutor(t, &TaskContext{Doc: doc, Tenant: entity.Tenant{ID: "tenant"}}, "pipeline", 10)
			store := &sensitiveMetadataEngine{existing: map[string]any{"owner": "team", "category": "old"}}
			if unsafe {
				store.existing["phone"] = "13812345678"
			}
			executor.deps.Engine = store
			ctx, session, err := sensitive.WithSession(context.Background(), &sensitive.Processor{Engine: e}, "doc", "run", "guide.txt")
			if err != nil {
				t.Fatal(err)
			}
			err = executor.persistSensitiveMetadata(ctx, session, map[string]any{"category": "new"})
			if unsafe {
				if sensitive.Reason(err) != "SP_RESCAN_HIT" || store.written != nil {
					t.Fatalf("unsafe merge written: %v", err)
				}
			} else if err != nil || store.written["owner"] != "team" || store.written["category"] != "new" {
				t.Fatalf("incorrect merged metadata: %#v, %v", store.written, err)
			}
		})
	}
}
