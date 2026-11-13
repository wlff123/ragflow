package chunker

import (
	"regexp"
	"strings"

	"ragflow/internal/sensitive"
)

// Treat typed placeholders as indivisible text even under a tiny token budget.
// This is only a splitting rule; it never exempts text from sensitive scanning.
var placeholderAtom = regexp.MustCompile(sensitive.PlaceholderPattern)

// placeholderAtoms skips the regex for the common case of text without placeholders.
func placeholderAtoms(text string) [][]int {
	if !strings.Contains(text, sensitive.PlaceholderPrefix) {
		return nil
	}
	return placeholderAtom.FindAllStringIndex(text, -1)
}

func delimiterMatches(text string, pattern *regexp.Regexp) [][]int {
	matches := pattern.FindAllStringIndex(text, -1)
	atoms := placeholderAtoms(text)
	out := matches[:0]
	i := 0
	for _, m := range matches {
		for i < len(atoms) && atoms[i][1] <= m[0] {
			i++
		}
		if i < len(atoms) && m[1] > atoms[i][0] && m[0] < atoms[i][1] {
			continue
		}
		out = append(out, m)
	}
	return out
}

// placeholderCut adjusts a byte offset. A prefix keeps the whole leading atom;
// a suffix drops a partial atom so overlap cannot exceed its available budget.
func placeholderCut(text string, cut int, suffix bool) int {
	for _, atom := range placeholderAtoms(text) {
		if atom[0] < cut && cut < atom[1] {
			if suffix || atom[0] == 0 {
				return atom[1]
			}
			return atom[0]
		}
	}
	return cut
}
