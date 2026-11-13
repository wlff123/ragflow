package parser

import (
	"context"

	"ragflow/internal/sensitive"
)

// TextBlockBoundary marks a complete paragraph/block, not a split text fragment.
// The ingestion cleaner consumes this internal marker before publishing output.
const TextBlockBoundary = "_sensitive_text_block"

func sensitiveBlockItems(ctx context.Context, items []map[string]any) []DocItem {
	if sensitive.FromContext(ctx) != nil {
		for _, item := range items {
			if item[DocTypeKey] == DocTypeText {
				item[TextBlockBoundary] = true
			}
		}
	}
	return MapsToItems(items)
}
