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

package schema

// KeySanitizeReport is the Sanitizer output key carrying the node's
// SanitizeReport. After a run it is found in the Sanitizer node's entry of the
// pipeline run state.
const KeySanitizeReport = "sanitize_report"

// SanitizeReport summarizes one Sanitizer run over a document. It carries
// counts and rule ids only, never source text.
type SanitizeReport struct {
	// ReplacementCount is the number of placeholders written.
	ReplacementCount int `json:"replacement_count"`
	// RuleHits counts placeholders per rule id; empty when nothing matched.
	RuleHits map[string]int `json:"rule_hits"`
	// RulesVersion is the catalog_version of the rule set used.
	RulesVersion string `json:"rules_version"`
	// RulesSource is "builtin" or "external".
	RulesSource string `json:"rules_source"`
}
