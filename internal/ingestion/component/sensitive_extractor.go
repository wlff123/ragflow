package component

import (
	"context"
	"encoding/json"
	"errors"
	"ragflow/internal/sensitive"
)

// invokeExtractorChat is shared by ordinary extraction and automatic tagging.
// It checks fitted messages and performs an initial response cleaning. Output
// owners must still check decoded values before caching or using them.
// Credentials and transport configuration are not business text.
func invokeExtractorChat(ctx context.Context, inv extractorChatInvoker, req extractorChatRequest) (*extractorChatResponse, error) {
	session := sensitive.FromContext(ctx)
	if session == nil {
		return inv.Chat(ctx, req)
	}
	// Copy the slice because requests may share template messages across workers.
	req.Messages = append(req.Messages[:0:0], req.Messages...)
	for i := range req.Messages {
		result, err := session.Processor.Engine.Clean(ctx, req.Messages[i].Content)
		if err != nil {
			return nil, session.Reject(err)
		}
		req.Messages[i].Content = result.Text
	}
	response, err := inv.Chat(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Provider errors may echo request or response content.
		return nil, safeModelError{retryable: isRetryableLLMError(err)}
	}
	if response == nil {
		return nil, errors.New("extractor: empty model response")
	}
	// JSON is cleaned by value so key context is kept. A valid JSON response the
	// structural cleaner cannot represent (duplicate keys, deep nesting) is
	// discarded: text cleaning would lose that context. It is a model output
	// error, not a document safety failure, so it is not latched.
	var result sensitive.Result
	if json.Valid([]byte(response.Content)) {
		result, err = session.Processor.Engine.CleanJSON(ctx, response.Content)
		if sensitive.Reason(err) == "SP_STRUCTURE_INVALID" {
			return nil, errUncheckableModelJSON
		}
	} else {
		result, err = session.Processor.Engine.Clean(ctx, response.Content)
	}
	if err != nil {
		return nil, session.Reject(err)
	}
	copy := *response
	copy.Content = result.Text
	return &copy, nil
}

var errUncheckableModelJSON = errors.New("extractor: model returned JSON that cannot be checked by value")

// safeModelError retains retry policy without retaining provider payloads.
type safeModelError struct{ retryable bool }

func (safeModelError) Error() string { return "extractor: model request failed" }

func cleanExtractorMetadata(ctx context.Context, value map[string]any) (map[string]any, error) {
	session := sensitive.FromContext(ctx)
	if session == nil || value == nil {
		return value, nil
	}
	cleaned, _, err := session.Processor.Engine.CleanValue(ctx, value)
	if err != nil {
		return nil, session.Reject(err)
	}
	return cleaned.(map[string]any), nil
}
