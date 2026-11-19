//
//  Copyright 2026 The InfiniFlow Authors. All Rights Reserved.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

package sanitize

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// ruleCount is the number of rules required by chapter 7 of the requirement.
const ruleCount = 20

// Replacement scopes.
const (
	scopeFull                = "full"
	scopeValueAfterSeparator = "value_after_separator"
)

// Rule sources reported in RulesInfo.
const (
	SourceBuiltin  = "builtin"
	SourceExternal = "external"
)

//go:embed rules/sensitive_rules.yaml
var builtinRules []byte

// rule is one entry of the rule catalog.
type rule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"display_name"`
	Scope    string `yaml:"replace_scope"`
	Priority int    `yaml:"priority"`
	Pattern  string `yaml:"pattern"`
}

// catalog is the decoded rule file.
type catalog struct {
	Version string `yaml:"catalog_version"`
	Rules   []rule `yaml:"rules"`
}

// decodeCatalog strictly decodes exactly one YAML document: unknown fields and
// trailing documents are rejected.
func decodeCatalog(r io.Reader) (*catalog, error) {
	var c catalog
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return nil, ErrRulesUnavailable
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrRulesUnavailable
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// validate checks the catalog shape: a version, exactly ruleCount rules, unique
// ids, a name usable inside a placeholder, a known scope and a pattern.
// Pattern compilation is checked separately by compileRules.
func (c *catalog) validate() error {
	if strings.TrimSpace(c.Version) == "" || len(c.Rules) != ruleCount {
		return ErrRulesUnavailable
	}
	ids := make(map[string]bool, len(c.Rules))
	for _, r := range c.Rules {
		if r.ID == "" || ids[r.ID] || r.Pattern == "" ||
			strings.TrimSpace(r.Name) == "" || strings.ContainsAny(r.Name, "[]\r\n") ||
			(r.Scope != scopeFull && r.Scope != scopeValueAfterSeparator) {
			return ErrRulesUnavailable
		}
		ids[r.ID] = true
	}
	return nil
}

// conformsTo reports whether c keeps the rule set of baseline: the same ids,
// each with the same display name and replacement scope. Only patterns,
// priorities and the catalog version may differ, so an override can tune
// matching but can never add, drop or rename a rule type.
//
// Both catalogs are validated (exactly ruleCount rules with unique ids), so
// matching every id of c against baseline also covers the reverse direction.
func (c *catalog) conformsTo(baseline *catalog) bool {
	want := make(map[string]rule, len(baseline.Rules))
	for _, r := range baseline.Rules {
		want[r.ID] = r
	}
	for _, r := range c.Rules {
		b, ok := want[r.ID]
		if !ok || b.Name != r.Name || b.Scope != r.Scope {
			return false
		}
	}
	return true
}

// builtinCatalog decodes the embedded rule file.
func builtinCatalog() (*catalog, error) {
	return decodeCatalog(bytes.NewReader(builtinRules))
}
