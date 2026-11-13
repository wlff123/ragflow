package common

// IsDatasetCompilationChunk identifies compiled dataset artifacts without a source document.
func IsDatasetCompilationChunk(chunk map[string]any) bool {
	docID, _ := chunk["doc_id"].(string)
	kbID, _ := chunk["kb_id"].(string)
	compileKind, _ := chunk["compile_kwd"].(string)
	return chunk["scope_kwd"] == "dataset" && compileKind != "" && docID != "" && docID == kbID
}
