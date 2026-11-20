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
	"context"
	"io"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// SanitizeHTML processes a body explicitly declared as HTML.
func (s *Sanitizer) SanitizeHTML(ctx context.Context, text string) (Result, error) {
	return s.htmlBody(ctx, text, 0)
}

func (s *Sanitizer) htmlBody(ctx context.Context, text string, depth int) (Result, error) {
	var out Result
	var b strings.Builder
	var visible []string
	flush := func() error {
		var err error
		if len(visible) > 1 {
			err = s.checkResidual(ctx, strings.Join(visible, ""))
		}
		visible = visible[:0]
		return err
	}
	z := html.NewTokenizer(strings.NewReader(text))
	var rawText bool
	for {
		if err := checkContext(ctx); err != nil {
			return Result{}, err
		}
		tt := z.Next()
		raw := string(z.Raw())
		if tt == html.ErrorToken {
			if z.Err() != io.EOF {
				return Result{}, z.Err()
			}
			if raw != "" {
				return Result{}, ErrResidual
			}
			if err := flush(); err != nil {
				return Result{}, err
			}
			out.Text = text
			if out.Count > 0 {
				out.Text = b.String()
			}
			return out, nil
		}
		token := z.Token()
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			if htmlTextBoundary(token.Data) {
				if err := flush(); err != nil {
					return Result{}, err
				}
			}
			rawText = false
			if tt == html.EndTagToken {
				break
			}
			switch token.Data {
			case "script", "style", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext":
				rawText = true
			}
			if len(token.Attr) > 0 {
				r, err := s.htmlAttrs(ctx, raw, token, depth)
				if err != nil {
					return Result{}, err
				}
				raw = r.Text
				out.Add(r)
			}
		case html.TextToken, html.CommentToken, html.DoctypeToken:
			r, err := s.Sanitize(ctx, token.Data)
			if err != nil {
				return Result{}, err
			}
			if tt == html.TextToken && !rawText {
				visible = append(visible, r.Text)
			}
			if r.Count > 0 {
				out.Add(r)
				token.Data = r.Text
				if tt == html.TextToken && rawText {
					raw = r.Text
				} else {
					raw = token.String()
				}
			}
		}
		b.WriteString(raw)
	}
}

// The tokenizer supplies decoded values. Source ranges preserve spelling and layout.
var htmlAttr = regexp.MustCompile(`^[\t\n\f\r /]*([^\t\n\f\r />=]+)(?:[\t\n\f\r ]*=[\t\n\f\r ]*("[^"]*"|'[^']*'|[^\t\n\f\r >]*))?`)

func (s *Sanitizer) htmlAttrs(ctx context.Context, raw string, token html.Token, depth int) (Result, error) {
	out := Result{Text: raw}
	var b strings.Builder
	pos := strings.IndexAny(raw, " \t\n\r\f/>")
	last := 0
	for _, a := range token.Attr {
		m := htmlAttr.FindStringSubmatchIndex(raw[pos:])
		if m == nil || !strings.EqualFold(raw[pos+m[2]:pos+m[3]], a.Key) {
			return Result{}, ErrResidual
		}
		name := raw[pos+m[2] : pos+m[3]]
		start := pos
		pos += m[1]
		if m[4] < 0 {
			continue
		}
		var r Result
		var err error
		if token.Data == "iframe" && a.Key == "srcdoc" {
			if depth >= 64 {
				return Result{}, ErrResidual
			}
			r, err = s.htmlBody(ctx, a.Val, depth+1)
		} else {
			r, err = s.SanitizeField(ctx, name, a.Val)
		}
		if err != nil {
			return Result{}, err
		}
		if r.Count == 0 {
			continue
		}
		literal := start + m[4]
		q := byte('"')
		if raw[literal] == '\'' {
			q = '\''
		}
		b.WriteString(raw[last:literal])
		b.WriteByte(q)
		b.WriteString(html.EscapeString(r.Text))
		b.WriteByte(q)
		last = pos
		out.Add(r)
	}
	if out.Count > 0 {
		b.WriteString(raw[last:])
		out.Text = b.String()
	}
	return out, nil
}

func htmlTextBoundary(tag string) bool {
	switch tag {
	case "br", "td", "th", "table", "caption",
		"h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "pre", "tr", "blockquote", "div",
		"section", "article", "header", "footer", "main", "nav", "aside", "address", "hgroup", "search", "center",
		"ul", "ol", "menu", "dl", "dt", "dd", "figure", "figcaption", "details", "summary", "dialog", "form", "fieldset", "legend", "hr", "iframe", "xmp", "plaintext":
		return true
	}
	return false
}
