package sensitive

import (
	"encoding/json"
	"strings"
)

type pipelineNode struct {
	Upstream   []string `json:"upstream"`
	Downstream []string `json:"downstream"`
	Object     struct {
		Name   string         `json:"component_name"`
		Params map[string]any `json:"params"`
	} `json:"obj"`
}

// ValidatePipeline checks the execution graph after the same shallow per-node
// override used by canvas.applyOverrideParams. It does not certify component
// implementations: those still need their pre-model and pre-write checks.
func ValidatePipeline(dsl []byte, overrides map[string]any) error {
	var root map[string]any
	if json.Unmarshal(dsl, &root) != nil {
		return Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	for _, key := range []string{"history", "memory", "messages", "path", "retrieval", "variables"} {
		if !emptyPipelineValue(root[key]) {
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
	}
	if globals, exists := root["globals"]; exists {
		m, ok := globals.(map[string]any)
		if !ok {
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
		for key, value := range m {
			if key != "sys.history" || !emptyPipelineValue(value) {
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
		}
	}
	var graph struct {
		Components map[string]pipelineNode `json:"components"`
	}
	if json.Unmarshal(dsl, &graph) != nil || len(graph.Components) < 4 {
		return Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	// Like canvas.buildNodeBody, apply only map overrides keyed by a graph node;
	// other parser_config keys (e.g. dataset "metadata") never reach a component.
	for id, override := range overrides {
		node, ok := graph.Components[id]
		params, isMap := override.(map[string]any)
		if !ok || !isMap {
			continue
		}
		if node.Object.Params == nil {
			node.Object.Params = map[string]any{}
		}
		for k, v := range params {
			node.Object.Params[k] = v
		}
		graph.Components[id] = node
	}
	start := ""
	for id, node := range graph.Components {
		if len(node.Upstream) > 1 || len(node.Downstream) > 1 || invalidPipelineParams(node.Object.Params) {
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
		if len(node.Upstream) == 0 {
			if start != "" {
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
			start = id
		}
	}
	if start == "" {
		return Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	visited := map[string]bool{}
	previous := ""
	phase := 0
	tokenizers := 0
	for id := start; id != ""; {
		node, ok := graph.Components[id]
		if !ok || visited[id] {
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
		visited[id] = true
		if previous != "" && (len(node.Upstream) != 1 || node.Upstream[0] != previous) {
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
		name := strings.ToLower(node.Object.Name)
		switch phase {
		case 0:
			if name != "file" {
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
			phase = 1
		case 1:
			if name != "parser" {
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
			phase = 2
		case 2:
			switch name {
			case "generalchunker", "onechunker", "titlechunker", "manualchunker", "tokenchunker", "pagechunker", "qachunker", "tablechunker", "grouptitlechunker", "hierarchytitlechunker":
				phase = 3
			default:
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
		case 3:
			if name == "tokenizer" {
				tokenizers++
				phase = 4
			} else if name != "extractor" {
				return Failure("SP_PIPELINE_NOT_ALLOWED")
			}
		default:
			return Failure("SP_PIPELINE_NOT_ALLOWED")
		}
		previous = id
		id = ""
		if len(node.Downstream) == 1 {
			id = node.Downstream[0]
		}
	}
	if len(visited) != len(graph.Components) || tokenizers != 1 {
		return Failure("SP_PIPELINE_NOT_ALLOWED")
	}
	return nil
}

func invalidPipelineParams(params map[string]any) bool {
	for k, v := range params {
		switch k {
		case "exception_method", "exception_goto", "exception_default_value", "ignore_error", "inputs", "input", "binary", "json", "text", "content", "chunks", "doc_id", "file", "bucket", "path":
			if !emptyPipelineValue(v) {
				return true
			}
		case "outputs":
			outputs, ok := v.(map[string]any)
			if !ok {
				return true
			}
			for _, output := range outputs {
				definition, ok := output.(map[string]any)
				if !ok {
					return true
				}
				if value, exists := definition["value"]; exists && !emptyPipelineValue(value) {
					return true
				}
			}
		}
	}
	return false
}

func emptyPipelineValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case bool:
		return !v
	case string:
		return v == ""
	case []any:
		return len(v) == 0
	case []string:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		return false
	}
}
