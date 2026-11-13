package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"strings"
	"testing"
	"time"
)

func TestLogCleanerFailsClosed(t *testing.T) {
	t.Cleanup(func() { SetLogCleaner(nil) })
	for name, clean := range map[string]func(context.Context, []byte) ([]byte, error){
		"error":   func(context.Context, []byte) ([]byte, error) { return nil, errors.New("private error") },
		"panic":   func(context.Context, []byte) ([]byte, error) { panic("private panic") },
		"invalid": func(context.Context, []byte) ([]byte, error) { return []byte("bad json"), nil },
		"cancel":  func(ctx context.Context, b []byte) ([]byte, error) { <-ctx.Done(); return b, nil },
	} {
		t.Run(name, func(t *testing.T) {
			SetLogCleaner(clean)
			if got := CleanLogText("private source"); got != HiddenLogContent {
				t.Fatalf("not hidden: %q", got)
			}
		})
	}
	SetLogCleaner(func(context.Context, []byte) ([]byte, error) {
		t.Fatal("oversized input reached cleaner")
		return nil, nil
	})
	if CleanLogText(strings.Repeat("x", maxLogContentBytes)) != HiddenLogContent {
		t.Fatal("oversized input not hidden")
	}
	SetLogCleaner(nil)
	if CleanLogText("ordinary") != "ordinary" {
		t.Fatal("disabled cleaner changed output")
	}
}

func TestLogCorePreservesFieldEncoding(t *testing.T) {
	t.Cleanup(func() { SetLogCleaner(nil) })
	config := zap.NewProductionEncoderConfig()
	config.TimeKey = ""
	config.EncodeDuration = zapcore.SecondsDurationEncoder
	config.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000-07:00")
	now := time.Date(2026, 11, 17, 12, 34, 56, 123000000, time.UTC)
	fields := []zap.Field{
		zap.Duration("latency", 100*time.Millisecond), zap.Time("at", now),
		zap.Durations("delays", []time.Duration{100 * time.Millisecond, time.Second}),
		zap.Times("times", []time.Time{now}),
	}
	for _, enabled := range []bool{false, true} {
		for _, bound := range []bool{false, true} {
			SetLogCleaner(nil)
			if enabled {
				SetLogCleaner(func(_ context.Context, b []byte) ([]byte, error) { return b, nil })
			}
			var original, cleaned bytes.Buffer
			base := func(b *bytes.Buffer) zapcore.Core {
				return zapcore.NewCore(zapcore.NewJSONEncoder(config), zapcore.AddSync(b), zapcore.InfoLevel)
			}
			before, after := zap.New(base(&original)), zap.New(newCleaningCore(base(&cleaned), config))
			if bound {
				before.With(fields...).Info("timing", zap.String("status", "ok"))
				after.With(fields...).Info("timing", zap.String("status", "ok"))
			} else {
				before.Info("timing", fields...)
				after.Info("timing", fields...)
			}
			var want, got map[string]json.RawMessage
			if err := json.Unmarshal(original.Bytes(), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(cleaned.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			for key, value := range want {
				if !bytes.Equal(value, got[key]) {
					t.Fatalf("enabled=%v bound=%v field=%s: want %s, got %s", enabled, bound, key, value, got[key])
				}
			}
		}
	}
}

type panickingLogValue struct{}

func (panickingLogValue) MarshalJSON() ([]byte, error) { panic("private payload") }

func TestLogCoreHidesUnserializableFields(t *testing.T) {
	SetLogCleaner(func(_ context.Context, b []byte) ([]byte, error) { return b, nil })
	t.Cleanup(func() { SetLogCleaner(nil) })
	core, entries := observer.New(zapcore.InfoLevel)
	logger := zap.New(newCleaningCore(core, zap.NewProductionEncoderConfig()))
	logger.Info("private message", zap.Any("value", panickingLogValue{}))
	if entries.Len() != 1 || entries.All()[0].Message != HiddenLogContent || len(entries.All()[0].Context) != 0 {
		t.Fatal("unsafe fallback")
	}
}
