package sensitive

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestOriginalStoreCanceledPutCanBeCleaned(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	objectPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, r.Body)
			objectPath = r.URL.Path
			cancel() // Object accepted, but the caller can no longer receive success.
			w.WriteHeader(http.StatusForbidden)
		case http.MethodDelete:
			if r.URL.Path != objectPath {
				t.Error("cleanup used a different location")
			}
			objectPath = ""
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	store, err := NewOriginalStore(OriginalStorageConfig{Endpoint: server.URL, Region: "test", Bucket: "isolated", AccessKey: "test", SecretKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	location, err := NewOriginalLocation(strings.Repeat("a", 32), strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOriginal(ctx, location, "guide.txt", []byte("synthetic original")); Reason(err) != "SP_ORIGINAL_UNAVAILABLE" {
		t.Fatalf("PUT result: %v", err)
	}
	mu.Lock()
	present := objectPath != ""
	mu.Unlock()
	if !present {
		t.Fatal("fixture did not accept the object")
	}
	if err := store.Delete(t.Context(), location); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if objectPath != "" {
		t.Fatal("object retained")
	}
}

func TestOriginalStoreWireContract(t *testing.T) {
	var saved []byte
	var originalName, objectPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "13812345678") {
			t.Error("original filename leaked into key")
		}
		switch r.Method {
		case http.MethodPut:
			objectPath = r.URL.Path
			originalName = r.Header.Get("X-Amz-Meta-Original-Name")
			saved, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			if r.URL.Path != "/isolated" && r.URL.Path != objectPath {
				w.WriteHeader(http.StatusNotFound)
			}
		case http.MethodGet:
			w.Header().Set("X-Amz-Meta-Original-Name", originalName)
			w.Write(saved)
		case http.MethodDelete:
			saved = nil
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	store, err := NewOriginalStore(OriginalStorageConfig{Endpoint: server.URL, Region: "test", Bucket: "isolated", AccessKey: "test-access", SecretKey: "test-secret", Prefix: "raw"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = store.Check(ctx); err != nil {
		t.Fatal(err)
	}
	name := "客户_13812345678.pdf"
	location, err := NewOriginalLocation(strings.Repeat("a", 32), strings.Repeat("b", 32))
	if err != nil {
		t.Fatal(err)
	}
	err = store.PutOriginal(ctx, location, name, []byte("original content"))
	if err != nil {
		t.Fatal(err)
	}
	if originalName != url.QueryEscape(name) || strings.Contains(location, name) {
		t.Fatal("original metadata/key contract failed")
	}
	if exists, err := store.Exists(ctx, location); err != nil || !exists {
		t.Fatalf("%v %v", exists, err)
	}
	original, err := store.OpenOriginal(ctx, location)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(original.Body)
	original.Body.Close()
	if err != nil || original.Name != name || string(body) != "original content" {
		t.Fatal("original did not round-trip")
	}
	if err = store.Delete(ctx, location); err != nil || len(saved) != 0 {
		t.Fatal("delete failed", err)
	}
	if _, err = store.OpenOriginal(ctx, "../../secret"); Reason(err) != "SP_ORIGINAL_UNAVAILABLE" {
		t.Fatal("invalid object location accepted")
	}
}

func TestOriginalStoreDoesNotExposeStorageErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>raw-secret-name</Message></Error>`)
	}))
	defer server.Close()
	store, err := NewOriginalStore(OriginalStorageConfig{Endpoint: server.URL, Region: "test", Bucket: "isolated", AccessKey: "test", SecretKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Check(context.Background())
	if Reason(err) != "SP_ORIGINAL_UNAVAILABLE" || strings.Contains(err.Error(), "raw-secret-name") {
		t.Fatal(err)
	}
}
