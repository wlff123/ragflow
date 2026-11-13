package config

import (
	"testing"

	"github.com/spf13/viper"
	"ragflow/internal/sensitive"
)

func TestBundledSensitiveConfig(t *testing.T) {
	v := viper.New()
	v.SetConfigFile("../../../conf/service_conf.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := cfg.ParseSensitiveConfig(v); err != nil {
		t.Fatal(err)
	}
	settings := cfg.GetSensitiveSettings()
	if settings == nil || !settings.OriginalStorage.CreateBucket || settings.RulesPath == "" {
		t.Fatal("bundled deployment lacks sensitive processing defaults")
	}
	if _, err := sensitive.NewOriginalStore(settings.OriginalStorage); err != nil {
		t.Fatal(err)
	}
	if settings.OriginalStorage.Bucket == v.GetString("minio.bucket") {
		t.Fatal("originals share the business storage bucket")
	}
}
