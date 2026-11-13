package config

import (
	"ragflow/internal/sensitive"
	"time"

	"github.com/spf13/viper"
)

func (c *Config) ParseSensitiveConfig(v *viper.Viper) error {
	if !v.IsSet("sensitive_processing") {
		return nil
	}
	sub := v.Sub("sensitive_processing")
	if sub == nil {
		return sensitive.Failure("SP_CONFIG_INVALID")
	}
	settings := sensitive.Settings{RulesPath: "conf/sensitive_rules.yaml", MatchTimeout: 100 * time.Millisecond, DocumentBudget: 30 * time.Second, MinimumCharacters: 20, MinimumRatio: .05}
	if sub.IsSet("rules_path") {
		settings.RulesPath = sub.GetString("rules_path")
	}
	if sub.IsSet("match_timeout") {
		settings.MatchTimeout = sub.GetDuration("match_timeout")
	}
	if sub.IsSet("document_budget") {
		settings.DocumentBudget = sub.GetDuration("document_budget")
	}
	if sub.IsSet("minimum_characters") {
		settings.MinimumCharacters = sub.GetInt("minimum_characters")
	}
	if sub.IsSet("minimum_ratio") {
		settings.MinimumRatio = sub.GetFloat64("minimum_ratio")
	}
	settings.OriginalStorage = sensitive.OriginalStorageConfig{
		Endpoint: sub.GetString("original_storage.endpoint"), Region: sub.GetString("original_storage.region"), Bucket: sub.GetString("original_storage.bucket"),
		AccessKey: sub.GetString("original_storage.access_key"), SecretKey: sub.GetString("original_storage.secret_key"), Prefix: sub.GetString("original_storage.prefix"),
	}
	c.sensitive = &settings
	return nil
}

func (c *Config) GetSensitiveSettings() *sensitive.Settings {
	if c == nil {
		return nil
	}
	return c.sensitive
}
