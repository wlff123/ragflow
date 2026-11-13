package sensitive

import (
	"context"
	"io"
	"ragflow/internal/common"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const PlaceholderPrefix = "[敏感信息已移除："

// PlaceholderPattern matches any rendered placeholder; chunkers use it to keep
// placeholders atomic.
const PlaceholderPattern = `\[敏感信息已移除：[^\[\]\r\n]+\]`

func placeholder(name string) string { return PlaceholderPrefix + name + "]" }

type Rule struct {
	ID       string `yaml:"id"`
	Name     string `yaml:"display_name"`
	Source   string `yaml:"source"`
	Scope    string `yaml:"replace_scope"`
	Priority int    `yaml:"priority"`
	Pattern  string `yaml:"pattern"`
}

type catalog struct {
	Version string `yaml:"catalog_version"`
	Rules   []Rule `yaml:"rules"`
}

type compiledRule struct {
	Rule
	regex *regexp2.Regexp
	order int
}

// Engine is immutable after loading and safe for concurrent requests.
type Engine struct {
	Version      string
	rules        []compiledRule
	placeholders map[string]bool
	budget       time.Duration
}

type Result struct {
	Text                string
	Count               int64
	SourceCharacters    int
	EffectiveCharacters int
}

// Add accumulates the counters of o; Text is left untouched.
func (r *Result) Add(o Result) {
	r.Count += o.Count
	r.SourceCharacters += o.SourceCharacters
	r.EffectiveCharacters += o.EffectiveCharacters
}

// Load compiles the entire catalog before making any rule available.
func Load(r io.Reader, matchTimeout, documentBudget time.Duration) (*Engine, error) {
	var c catalog
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if d.Decode(&c) != nil || c.Version == "" || len(c.Rules) != 21 || matchTimeout <= 0 || documentBudget <= 0 {
		return nil, Failure("SP_RULES_LOAD_FAILED")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, Failure("SP_RULES_LOAD_FAILED")
	}
	e := &Engine{Version: c.Version, budget: documentBudget, placeholders: map[string]bool{}}
	ids := map[string]bool{}
	for i, rule := range c.Rules {
		if rule.ID == "" || ids[rule.ID] || rule.Name == "" || strings.ContainsAny(rule.Name, "[]\r\n") || rule.Pattern == "" ||
			(rule.Scope != "full" && rule.Scope != "value_after_separator") ||
			(i < 20 && rule.Source != "requirement") || (i == 20 && rule.Source != "supplement") {
			return nil, Failure("SP_RULES_LOAD_FAILED")
		}
		ids[rule.ID] = true
		rx, err := regexp2.Compile(rule.Pattern, regexp2.None)
		if err != nil {
			return nil, Failure("SP_RULES_LOAD_FAILED")
		}
		rx.MatchTimeout = matchTimeout
		if hit, err := rx.MatchString(""); err != nil || hit {
			return nil, Failure("SP_RULES_LOAD_FAILED")
		}
		e.rules = append(e.rules, compiledRule{rule, rx, i})
		e.placeholders[placeholder(rule.Name)] = true
	}
	for p := range e.placeholders {
		for _, rule := range e.rules {
			if hit, err := rule.regex.MatchString(p); err != nil || hit {
				return nil, Failure("SP_RULES_LOAD_FAILED")
			}
		}
	}
	return e, nil
}

type span struct {
	start, end int
	rule       compiledRule
}

func (e *Engine) mask(text string) []rune {
	r := []rune(text)
	for i := 0; i < len(r); i++ {
		if r[i] != '[' {
			continue
		}
		for j := i + 1; j < len(r) && j-i < 128; j++ {
			if r[j] != ']' {
				continue
			}
			if e.placeholders[string(r[i:j+1])] {
				for k := i; k <= j; k++ {
					r[k] = '\uffff'
				}
				i = j
			}
			break
		}
	}
	return r
}

func valueRune(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("_+-/=", r)
}

func checkBudget(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Now().After(deadline) {
		return Failure("SP_REGEX_TIMEOUT")
	}
	return nil
}

func (e *Engine) matches(ctx context.Context, text string, deadline time.Time) ([]span, error) {
	runes := e.mask(text)
	var found []span
	for _, rule := range e.rules {
		if err := checkBudget(ctx, deadline); err != nil {
			return nil, err
		}
		m, err := rule.regex.FindRunesMatch(runes)
		for m != nil && err == nil {
			if err := checkBudget(ctx, deadline); err != nil {
				return nil, err
			}
			s := span{m.Index, m.Index + m.Length, rule}
			if s.start == s.end {
				return nil, Failure("SP_RULES_LOAD_FAILED")
			}
			if rule.Scope == "value_after_separator" {
				for s.start < s.end && runes[s.start] != ':' && runes[s.start] != '=' {
					s.start++
				}
				if s.start == s.end {
					return nil, Failure("SP_RULES_LOAD_FAILED")
				}
				if runes[s.start] == '=' && s.start+1 < s.end && (runes[s.start+1] == ':' || runes[s.start+1] == '>') {
					s.start++
				}
				s.start++
				for s.start < s.end && (unicode.IsSpace(runes[s.start]) || runes[s.start] == '\'' || runes[s.start] == '"') {
					s.start++
				}
				s.end = s.start
				for s.end < len(runes) && valueRune(runes[s.end]) {
					s.end++
				}
			}
			// Supplement: a long block matches the pattern's key-area branch, which
			// can run past END; cut at END inside the match. An unclosed block keeps
			// the whole matched key area and never extends into later text.
			if rule.ID == "PEM_BLOCK" {
				body := string(runes[s.start:s.end])
				labelEnd := strings.Index(body[len("-----BEGIN "):], "-----")
				if labelEnd < 0 {
					return nil, Failure("SP_STRUCTURE_INVALID")
				}
				endMarker := "-----END " + body[len("-----BEGIN "):len("-----BEGIN ")+labelEnd] + "-----"
				if at := strings.Index(body, endMarker); at >= 0 {
					s.end = s.start + len([]rune(body[:at+len(endMarker)]))
				}
			}
			if s.end <= s.start {
				return nil, Failure("SP_STRUCTURE_INVALID")
			}
			found = append(found, s)
			m, err = rule.regex.FindNextMatch(m)
		}
		if err != nil {
			// regexp2 errors include the complete input; never log the error.
			common.Warn("sensitive regex timeout", zap.String("rule_id", rule.ID), zap.Int("characters", len(runes)))
			return nil, Failure("SP_REGEX_TIMEOUT")
		}
	}
	return found, checkBudget(ctx, deadline)
}

func preferred(a, b span) span {
	if a.start <= b.start && a.end >= b.end && (a.start != b.start || a.end != b.end) {
		return a
	}
	if b.start <= a.start && b.end >= a.end && (a.start != b.start || a.end != b.end) {
		return b
	}
	if a.rule.Priority != b.rule.Priority {
		if a.rule.Priority > b.rule.Priority {
			return a
		}
		return b
	}
	if a.end-a.start != b.end-b.start {
		if a.end-a.start > b.end-b.start {
			return a
		}
		return b
	}
	if a.rule.order < b.rule.order {
		return a
	}
	return b
}

// mergeGap reports whether adjacent same-rule hits may share one placeholder:
// only spaces and list punctuation may separate them. Line breaks, tabs and
// '|' delimit lines, columns and table cells, so hits across them stay apart.
func mergeGap(gap []rune) bool {
	for _, r := range gap {
		if !strings.ContainsRune(" \u00a0\u3000，、,;；/", r) {
			return false
		}
	}
	return true
}

func (e *Engine) replacementPlan(ctx context.Context, text string, deadline time.Time) ([]span, error) {
	found, err := e.matches(ctx, text, deadline)
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].start == found[j].start {
			return found[i].end > found[j].end
		}
		return found[i].start < found[j].start
	})
	runes := []rune(text)
	var merged []span
	var winner span
	for _, s := range found {
		if len(merged) == 0 {
			merged = append(merged, s)
			winner = s
			continue
		}
		last := &merged[len(merged)-1]
		if s.start < last.end {
			winner = preferred(winner, s)
			last.rule = winner.rule
			if s.end > last.end {
				last.end = s.end
			}
			continue
		}
		if last.rule.ID == s.rule.ID && mergeGap(runes[last.end:s.start]) {
			last.end = s.end
		} else {
			merged = append(merged, s)
			winner = s
		}
	}
	return merged, checkBudget(ctx, deadline)
}

func (e *Engine) clean(ctx context.Context, text string, deadline time.Time) (Result, error) {
	_, result, err := e.cleanSegments(ctx, []string{text}, deadline)
	return result, err
}

func (e *Engine) scanText(ctx context.Context, text string) error {
	found, err := e.matches(ctx, text, e.deadline(ctx))
	if err != nil {
		return err
	}
	if len(found) > 0 {
		return Failure("SP_RESCAN_HIT")
	}
	return nil
}

func (e *Engine) Characters(text string) int {
	n := 0
	for _, r := range e.mask(text) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			n++
		}
	}
	return n
}

func ValidateContent(source, effective, minimum int, ratio float64) error {
	if minimum < 0 || ratio < 0 || ratio > 1 {
		return Failure("SP_CONFIG_INVALID")
	}
	if effective == 0 || effective < minimum || float64(effective) < float64(source)*ratio {
		return Failure("SP_NO_VALID_CONTENT")
	}
	return nil
}
