package sensitive

import (
	"bytes"
	"encoding/json"
	"io"
)

type DatasetConfig struct {
	DefaultEnabled bool `json:"default_enabled"`
	Enforced       bool `json:"enforced"`
}

// DecodeDatasetConfig rejects null, unknown fields and non-boolean values.
// An omitted configuration uses the caller's defaults (create versus update).
func DecodeDatasetConfig(raw json.RawMessage, defaults DatasetConfig) (DatasetConfig, error) {
	if len(raw) == 0 {
		return defaults, nil
	}
	m, err := booleanObject(raw)
	if err != nil {
		return DatasetConfig{}, err
	}
	for k, v := range m {
		switch k {
		case "default_enabled":
			defaults.DefaultEnabled = v
		case "enforced":
			defaults.Enforced = v
		default:
			return DatasetConfig{}, Failure("SP_CONFIG_INVALID")
		}
	}
	if defaults.Enforced && !defaults.DefaultEnabled {
		return DatasetConfig{}, Failure("SP_CONFIG_INVALID")
	}
	return defaults, nil
}

func ResolveEnabled(raw json.RawMessage, config DatasetConfig) (bool, error) {
	value := config.DefaultEnabled
	if len(raw) > 0 {
		m, err := booleanObject(raw)
		if err != nil {
			return false, err
		}
		if len(m) != 1 {
			return false, Failure("SP_CONFIG_INVALID")
		}
		v, ok := m["enabled"]
		if !ok {
			return false, Failure("SP_CONFIG_INVALID")
		}
		value = v
	}
	if config.Enforced && !value {
		return false, Failure("SP_ENFORCED")
	}
	return value, nil
}

func booleanObject(raw []byte) (map[string]bool, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := decodeJSON(d, 0)
	if err != nil {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, Failure("SP_CONFIG_INVALID")
	}
	out := map[string]bool{}
	for k, v := range m {
		b, ok := v.(bool)
		if !ok {
			return nil, Failure("SP_CONFIG_INVALID")
		}
		out[k] = b
	}
	return out, nil
}
