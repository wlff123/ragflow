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

const (
	placeholderPrefix = "[敏感信息已移除："
	placeholderSuffix = "]"

	// maskRune replaces every rune of an existing standard placeholder before
	// matching, so no rule can match inside (or across the edge of) a
	// placeholder. U+FFFF is a Unicode noncharacter that no rule matches.
	maskRune = '\uffff'

	// maxPlaceholderRunes bounds the search for a placeholder's closing
	// bracket; the longest rule name is far below it.
	maxPlaceholderRunes = 128
)

var placeholderPrefixRunes = []rune(placeholderPrefix)

// placeholder renders the standard placeholder for a rule name, for example
// "[敏感信息已移除：手机号]".
func placeholder(ruleName string) string {
	return placeholderPrefix + ruleName + placeholderSuffix
}

// maskPlaceholders masks, in place, every standard placeholder of a known rule
// in runes and returns runes. Only placeholders whose name belongs to the catalog are
// masked: a bracket that merely looks similar is still scanned. This makes
// sanitization idempotent: re-running it on its own output finds nothing.
func maskPlaceholders(runes []rune, known map[string]bool) []rune {
	for i := 0; i < len(runes); i++ {
		if !hasRunePrefix(runes[i:], placeholderPrefixRunes) {
			continue
		}
		for j := i + 1; j < len(runes) && j-i < maxPlaceholderRunes; j++ {
			if runes[j] != ']' {
				continue
			}
			if known[string(runes[i:j+1])] {
				for k := i; k <= j; k++ {
					runes[k] = maskRune
				}
				i = j
			}
			break
		}
	}
	return runes
}

func hasRunePrefix(runes, prefix []rune) bool {
	if len(runes) < len(prefix) {
		return false
	}
	for i, r := range prefix {
		if runes[i] != r {
			return false
		}
	}
	return true
}
