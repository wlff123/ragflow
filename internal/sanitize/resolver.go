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
	"sort"
	"strings"
)

// mergeSeparators are the only runes that may separate two hits of the same
// rule for them to share one placeholder: spaces and list punctuation. Line
// breaks, tabs and '|' delimit lines, columns and table cells, so hits across
// them stay separate.
const mergeSeparators = "  　，、,;；/"

// resolveSpans turns raw, possibly overlapping matches into the replacement
// plan: a sorted list of disjoint spans, each producing one placeholder.
//
//   - Overlapping matches are united into one span; its placeholder names the
//     preferred rule (see preferred).
//   - Adjacent matches of the same rule separated only by mergeSeparators are
//     merged into one span, so "a, b, c" of one type becomes one placeholder.
//
// len(plan) is the replacement count reported to callers.
func resolveSpans(found []span, runes []rune) []span {
	if len(found) == 0 {
		return nil
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].start != found[j].start {
			return found[i].start < found[j].start
		}
		return found[i].end > found[j].end
	})
	plan := []span{found[0]}
	winner := found[0]
	for _, s := range found[1:] {
		last := &plan[len(plan)-1]
		if s.start < last.end {
			winner = preferred(winner, s)
			last.rule = winner.rule
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		if last.rule.ID == s.rule.ID && onlySeparators(runes[last.end:s.start]) {
			last.end = s.end
			continue
		}
		plan = append(plan, s)
		winner = s
	}
	return plan
}

// preferred picks which of two overlapping matches names the placeholder: a
// match that strictly contains the other, then the higher priority, then the
// longer match, then the earlier catalog entry.
func preferred(a, b span) span {
	aLen, bLen := a.end-a.start, b.end-b.start
	if aLen != bLen {
		if a.start <= b.start && a.end >= b.end {
			return a
		}
		if b.start <= a.start && b.end >= a.end {
			return b
		}
	}
	if a.rule.Priority != b.rule.Priority {
		if a.rule.Priority > b.rule.Priority {
			return a
		}
		return b
	}
	if aLen != bLen {
		if aLen > bLen {
			return a
		}
		return b
	}
	if a.rule.order <= b.rule.order {
		return a
	}
	return b
}

func onlySeparators(gap []rune) bool {
	for _, r := range gap {
		if !strings.ContainsRune(mergeSeparators, r) {
			return false
		}
	}
	return true
}

// render writes text with every planned span replaced by its placeholder and
// returns the per-rule hit counts.
func render(runes []rune, plan []span) (string, map[string]int) {
	if len(plan) == 0 {
		return string(runes), nil
	}
	hits := make(map[string]int, len(plan))
	var b strings.Builder
	b.Grow(len(runes) + len(plan)*len(placeholderPrefix))
	pos := 0
	for _, s := range plan {
		writeRunes(&b, runes[pos:s.start])
		b.WriteString(placeholder(s.rule.Name))
		hits[s.rule.ID]++
		pos = s.end
	}
	writeRunes(&b, runes[pos:])
	return b.String(), hits
}

func writeRunes(b *strings.Builder, runes []rune) {
	for _, r := range runes {
		b.WriteRune(r)
	}
}
