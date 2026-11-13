package chunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ragflow/internal/dao"
	"ragflow/internal/entity/models"
	"ragflow/internal/sensitive"
	"ragflow/internal/server"
	"ragflow/internal/service"
)

func TestAddSensitiveChunkChecksStoredNameBeforeEmbedding(t *testing.T) {
	// A virtual document can predate the current rules and have no indexed
	// chunks whose title would otherwise be checked during preparation.
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer store.Close()
	configPath := filepath.Join(t.TempDir(), "service.yaml")
	config := fmt.Sprintf("sensitive_processing:\n  rules_path: ../../../conf/sensitive_rules.yaml\n  original_storage:\n    endpoint: %s\n    region: test\n    bucket: originals\n    access_key: test\n    secret_key: test\n", store.URL)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.Init(configPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(configPath, []byte("{}\n"), 0600); err != nil {
			t.Error(err)
			return
		}
		if err := server.Init(configPath); err != nil {
			t.Error(err)
		}
	})
	db := setupChunkTestDB(t)
	pushChunkTestDB(t, db)
	insertChunkTestKB(t, "kb-1", "user-1")
	insertChunkTestDoc(t, "doc-1", "kb-1")
	if err := db.Table("document").Where("id = ?", "doc-1").Updates(map[string]any{
		"type": "virtual", "location": "", "security_processing_enabled": true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	modelReached := errors.New("embedding resolver reached")
	for _, name := range []string{"Contact 13812345678.txt", "guide.txt"} {
		t.Run(name, func(t *testing.T) {
			if err := db.Table("document").Where("id = ?", "doc-1").Update("name", name).Error; err != nil {
				t.Fatal(err)
			}
			called := false
			engine := &addChunkTestEngine{}
			svc := &ChunkService{
				docEngine: engine, kbDAO: dao.NewKnowledgebaseDAO(), documentDAO: dao.NewDocumentDAO(),
				checkDatasetAccessFunc:  func(string) error { return nil },
				tokenizeFunc:            func(text, _ string) (string, error) { return text, nil },
				fineGrainedTokenizeFunc: func(text, _ string) (string, error) { return text, nil },
				getEmbeddingModelFunc: func(string, string) (*models.EmbeddingModel, error) {
					called = true
					return nil, modelReached
				},
			}
			_, err := svc.AddChunk(t.Context(), &service.AddChunkRequest{
				DatasetID: "kb-1", DocumentID: "doc-1",
				Content: "Ordinary operational documentation with enough useful text.",
			})
			if name == "guide.txt" {
				if !called || err == nil || !strings.Contains(err.Error(), modelReached.Error()) {
					t.Fatalf("safe name did not reach embedding: called=%v err=%v", called, err)
				}
			} else if called || sensitive.Reason(err) != "SP_RESCAN_HIT" {
				t.Fatalf("unsafe name must be rejected before embedding: called=%v err=%v", called, err)
			}
			if len(engine.insertedChunks) != 0 {
				t.Fatal("failed request wrote index chunks")
			}
		})
	}
}

func TestCleanManualFieldsCleansAuxiliaryValuesWithoutCountingThem(t *testing.T) {
	f, err := os.Open("../../../conf/sensitive_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e, err := sensitive.Load(f, time.Second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{
		"content_with_weight": "Operational documentation. Contact 13812345678",
		"question_kwd":        []string{"Contact 13812345678?"}, "important_kwd": []string{"13812345678"},
		"tag_kwd": []string{"13812345678"}, "tag_feas": map[string]float64{"13812345678": 1},
	}
	clean, result, err := cleanManualFields(context.Background(), e, fields)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 {
		t.Fatalf("auxiliary fields inflated body count: %d", result.Count)
	}
	b, _ := json.Marshal(clean)
	if strings.Contains(string(b), "13812345678") {
		t.Fatal("raw value retained")
	}
	if !strings.Contains(fields["content_with_weight"].(string), "13812345678") {
		t.Fatal("mutated caller input")
	}
	if _, err := validateTagFeatures(clean["tag_feas"]); err != nil {
		t.Fatal("tag score type changed", err)
	}
}
