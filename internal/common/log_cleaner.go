package common

import (
	"context"
	"encoding/json"
	"sort"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const HiddenLogContent = "[日志内容已隐藏：清洗失败]"
const maxLogContentBytes = 256 * 1024

type logCleaner struct {
	clean func(context.Context, []byte) ([]byte, error)
}

var activeLogCleaner atomic.Pointer[logCleaner]

// SetLogCleaner installs a JSON-to-JSON cleaner before serving requests. The
// callback must not log. Nil disables cleaning when sensitive processing is absent.
func SetLogCleaner(clean func(context.Context, []byte) ([]byte, error)) {
	if clean == nil {
		activeLogCleaner.Store(nil)
		return
	}
	activeLogCleaner.Store(&logCleaner{clean: clean})
}

// CleanLogValue preserves the caller's schema; unsupported values, key changes
// that cannot be decoded, timeouts and panics are hidden rather than passed through.
// It uses a fresh budget, never a document's context or replacement count.
func CleanLogValue[T any](value T, fallback T) (out T) {
	cleaner := activeLogCleaner.Load()
	if cleaner == nil {
		return value
	}
	out = fallback
	defer func() {
		if recover() != nil {
			out = fallback
		}
	}()
	b, err := json.Marshal(value)
	if err != nil || len(b) > maxLogContentBytes {
		return fallback
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	b, err = cleaner.clean(ctx, b)
	if err != nil || ctx.Err() != nil {
		return fallback
	}
	var decoded T
	if json.Unmarshal(b, &decoded) != nil {
		return fallback
	}
	return decoded
}

func CleanLogText(text string) string {
	if text == "" {
		return ""
	}
	return CleanLogValue(text, HiddenLogContent)
}

// cleaningCore sits before the console/file tee, including Logger.With, Sugar
// and StdLogger calls. Fields are materialized before cleaning, so credential
// keys, numeric values, reflected objects and errors keep their semantic context.
type cleaningCore struct {
	zapcore.Core
	fields  []zap.Field
	encoder zapcore.Encoder
}

func newCleaningCore(core zapcore.Core, config zapcore.EncoderConfig) *cleaningCore {
	// Encode only fields, using the same value encoders as the output core.
	config.MessageKey, config.LevelKey, config.TimeKey = "", "", ""
	config.NameKey, config.CallerKey, config.FunctionKey, config.StacktraceKey = "", "", "", ""
	return &cleaningCore{Core: core, encoder: zapcore.NewJSONEncoder(config)}
}

func (c *cleaningCore) encodeFields(fields []zap.Field) (map[string]json.RawMessage, error) {
	b, err := c.encoder.EncodeEntry(zapcore.Entry{}, fields)
	if err != nil {
		return nil, err
	}
	defer b.Free()
	var values map[string]json.RawMessage
	err = json.Unmarshal(b.Bytes(), &values)
	return values, err
}

func (c *cleaningCore) With(fields []zap.Field) zapcore.Core {
	all := append(append([]zap.Field(nil), c.fields...), c.snapshotLogFields(fields)...)
	return &cleaningCore{Core: c.Core, fields: all, encoder: c.encoder}
}

// Match zap's eager With semantics: do not retain mutable caller-owned objects
// until a later Write. Namespace markers must still apply to subsequent fields.
func (c *cleaningCore) snapshotLogFields(fields []zap.Field) (out []zap.Field) {
	defer func() {
		if recover() != nil {
			out = []zap.Field{zap.String("log_error", HiddenLogContent)}
		}
	}()
	for _, field := range fields {
		if field.Type == zapcore.NamespaceType {
			out = append(out, field)
			continue
		}
		values, err := c.encodeFields([]zap.Field{field})
		if err != nil {
			return []zap.Field{zap.String("log_error", HiddenLogContent)}
		}
		for key, value := range values {
			out = append(out, zap.Reflect(key, value))
		}
	}
	return out
}

func (c *cleaningCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

type logPayload struct {
	Message string                     `json:"message"`
	Name    string                     `json:"name"`
	Stack   string                     `json:"stack"`
	Fields  map[string]json.RawMessage `json:"fields"`
}

func (c *cleaningCore) Write(entry zapcore.Entry, fields []zap.Field) error {
	all := append(append([]zap.Field(nil), c.fields...), fields...)
	if activeLogCleaner.Load() == nil {
		return c.Core.Write(entry, all)
	}
	payload := c.clean(entry, all)
	entry.Message, entry.LoggerName, entry.Stack = payload.Message, payload.Name, payload.Stack
	keys := make([]string, 0, len(payload.Fields))
	for key := range payload.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	cleaned := make([]zap.Field, 0, len(keys))
	for _, key := range keys {
		cleaned = append(cleaned, zap.Reflect(key, payload.Fields[key]))
	}
	return c.Core.Write(entry, cleaned)
}

func (c *cleaningCore) clean(entry zapcore.Entry, fields []zap.Field) (out logPayload) {
	fallback := logPayload{Message: HiddenLogContent}
	out = fallback
	defer func() {
		if recover() != nil {
			out = fallback
		}
	}()
	values, err := c.encodeFields(fields)
	if err != nil {
		return fallback
	}
	return CleanLogValue(logPayload{entry.Message, entry.LoggerName, entry.Stack, values}, fallback)
}
