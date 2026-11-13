package component

import (
	"context"
	"encoding/json"
	"errors"
	eschema "github.com/cloudwego/eino/schema"
	"ragflow/internal/common"
	"ragflow/internal/sensitive"
	"strings"
	"testing"
)

type sensitiveChatProbe struct {
	t     *testing.T
	calls int
}

func TestSensitiveMetadataCleansDecodedResponseAndCache(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "fenced response", true: "cache hit"}[cached], func(t *testing.T) {
			ctx, _ := sensitiveParserContext(t, "guide.txt")
			response := "```json\n{\"phone\":\"\\u0031\\u0033\\u0038\\u0031\\u0032\\u0033\\u0034\\u0035\\u0036\\u0037\\u0038\"}\n```"
			stub := withStubChatInvoker(t, stubResponse{Content: response})
			store := newFakeCacheStore()
			c := newMetadataExtractor(common.MetadataFieldDef{Key: "phone", Type: "string"})
			in := extractorInputs{llmID: "model-1", modelID: "model-1", cache: store}
			schemaJSON, err := json.Marshal(common.Turn2JSONSchema(c.Param.Metadata.Metadata))
			if err != nil {
				t.Fatal(err)
			}
			if cached {
				setMetadataLLMCache(ctx, store, "model-1", string(schemaJSON), "chunk-1", map[string]any{"phone": "13812345678"})
			}
			chunk := map[string]any{"id": "chunk-1"}
			if err := c.runEnableMetadata(ctx, nil, in, chunk, "ordinary document content"); err != nil {
				t.Fatal(err)
			}
			value, hit := getMetadataLLMCache(ctx, store, "model-1", string(schemaJSON), "chunk-1")
			if !hit || value["phone"] == "13812345678" || value["phone"] == "" {
				t.Fatalf("unsafe cache: %#v", value)
			}
			if err := sensitive.FromContext(ctx).Processor.Engine.ScanValue(ctx, chunk["metadata"]); err != nil {
				t.Fatal(err)
			}
			if cached && stub.Calls() != 0 {
				t.Fatal("cache hit called model")
			}
		})
	}
}

type failingSensitiveChat struct{ err error }

func (p failingSensitiveChat) Chat(context.Context, extractorChatRequest) (*extractorChatResponse, error) {
	return nil, p.err
}

func TestSensitiveModelErrorPreservesRetryPolicy(t *testing.T) {
	for _, message := range []string{"401 unauthorized secret payload", "400 bad request secret payload", "429 secret payload", "503 secret payload"} {
		ctx, _ := sensitiveParserContext(t, "guide.txt")
		original := errors.New(message)
		_, err := invokeExtractorChat(ctx, failingSensitiveChat{original}, extractorChatRequest{})
		if err == nil || strings.Contains(err.Error(), "secret") || errors.Unwrap(err) != nil {
			t.Fatalf("unsafe error: %v", err)
		}
		if isRetryableLLMError(err) != isRetryableLLMError(original) {
			t.Fatalf("retry classification changed for %q", message)
		}
	}
}

func (p *sensitiveChatProbe) Chat(ctx context.Context, req extractorChatRequest) (*extractorChatResponse, error) {
	p.calls++
	for _, message := range req.Messages {
		if strings.Contains(message.Content, "13812345678") {
			p.t.Fatal("raw value reached model")
		}
	}
	return &extractorChatResponse{Content: `{"password":"abcdefgh1234","note":"normal text"}`}, nil
}

func TestSensitiveExtractorCleansActualRequestAndResponse(t *testing.T) {
	ctx, _ := sensitiveParserContext(t, "guide.txt")
	probe := &sensitiveChatProbe{t: t}
	messages := []eschema.Message{{Content: "customer phone 13812345678"}}
	response, err := invokeExtractorChat(ctx, probe, extractorChatRequest{Messages: messages})
	if err != nil {
		t.Fatal(err)
	}
	if probe.calls != 1 || strings.Contains(response.Content, "abcdefgh1234") || !strings.Contains(response.Content, "敏感信息已移除") {
		t.Fatal("response was not cleaned")
	}
	if !strings.Contains(messages[0].Content, "13812345678") {
		t.Fatal("shared input mutated")
	}
}

func TestSensitiveFailureSurvivesOptionalExtractorSkip(t *testing.T) {
	_, session := sensitiveParserContext(t, "guide.txt")
	session.Reject(sensitive.Failure("SP_REGEX_TIMEOUT"))
	if err := session.SealOutput(map[string]any{"chunks": []any{}}); sensitive.Reason(err) != "SP_REGEX_TIMEOUT" {
		t.Fatal("safety error swallowed")
	}
}

type contentSensitiveChat struct{ content string }

func (p contentSensitiveChat) Chat(context.Context, extractorChatRequest) (*extractorChatResponse, error) {
	return &extractorChatResponse{Content: p.content}, nil
}

func TestSensitiveUncheckableJSONResponseIsDiscarded(t *testing.T) {
	ctx, _ := sensitiveParserContext(t, "guide.txt")
	resp, err := invokeExtractorChat(ctx, contentSensitiveChat{`{"password":["abcdefgh1234"],"x":1,"x":2}`}, extractorChatRequest{})
	if !errors.Is(err, errUncheckableModelJSON) || resp != nil {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	if latched := sensitive.FromContext(ctx).Reject(nil); latched != nil {
		t.Fatalf("model output error latched as safety failure: %v", latched)
	}
}
