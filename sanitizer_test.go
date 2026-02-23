package htmlsanitizer_test

import (
	"strings"
	"testing"

	"github.com/njchilds90/htmlsanitizer"
	"golang.org/x/net/html"
)

func TestSanitize_ScriptStripped(t *testing.T) {
	input := `<p>Hello</p><script>alert('xss')</script>`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "script") {
		t.Errorf("script tag found in output: %s", got)
	}
	if !strings.Contains(got, "Hello") {
		t.Errorf("expected Hello in output: %s", got)
	}
}

func TestSanitize_JavascriptHrefBlocked(t *testing.T) {
	input := `<a href="javascript:alert(1)">click</a>`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "javascript") {
		t.Errorf("javascript href survived sanitization: %s", got)
	}
}

func TestSanitize_DataUriBlocked(t *testing.T) {
	input := `<img src="data:text/html,<script>alert(1)</script>">`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "data:") {
		t.Errorf("data URI survived sanitization: %s", got)
	}
}

func TestSanitize_AllowedTagPreserved(t *testing.T) {
	input := `<p><b>bold</b> and <i>italic</i></p>`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"<p>", "<b>", "<i>"} {
		if !strings.Contains(got, tag) {
			t.Errorf("expected %s in output: %s", tag, got)
		}
	}
}

func TestSanitize_StripDisallowed(t *testing.T) {
	p := &htmlsanitizer.Policy{
		AllowedTags:     []string{"p"},
		AllowedAttributes: map[string][]string{},
		AllowedSchemes:  []string{"https"},
		StripDisallowed: true,
	}
	input := `<p>keep</p><div>gone</div>`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "div") {
		t.Errorf("div should be stripped: %s", got)
	}
	if !strings.Contains(got, "keep") {
		t.Errorf("text inside p should survive: %s", got)
	}
}

func TestSanitize_EscapeDisallowed(t *testing.T) {
	p := &htmlsanitizer.Policy{
		AllowedTags:     []string{"p"},
		AllowedAttributes: map[string][]string{},
		AllowedSchemes:  []string{"https"},
		StripDisallowed: false,
	}
	input := `<p>keep</p><div>escaped</div>`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "<div>") {
		t.Errorf("div should be escaped not raw: %s", got)
	}
	if !strings.Contains(got, "escaped") {
		t.Errorf("text content should survive escaping: %s", got)
	}
}

func TestSanitize_RelativeURLAllowed(t *testing.T) {
	input := `<a href="/about">About</a>`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `href="/about"`) {
		t.Errorf("relative href should be preserved: %s", got)
	}
}

func TestSanitize_MaxDepth(t *testing.T) {
	p := htmlsanitizer.DefaultPolicy()
	p.MaxDepth = 2
	input := `<div><div><div><b>deep</b></div></div></div>`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	// The <b> is at depth 4, should not appear.
	if strings.Contains(got, "<b>") {
		t.Errorf("node beyond MaxDepth should be stripped: %s", got)
	}
}

func TestSanitize_Transformer(t *testing.T) {
	p := htmlsanitizer.DefaultPolicy()
	p.Transformers = []htmlsanitizer.Transformer{
		func(n *html.Node) *html.Node {
			if n.Type == html.ElementNode && n.Data == "a" {
				htmlsanitizer.SetAttr(n, "target", "_blank")
				htmlsanitizer.SetAttr(n, "rel", "noopener noreferrer")
			}
			return n
		},
	}
	input := `<a href="https://example.com">link</a>`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `target="_blank"`) {
		t.Errorf("transformer should add target=_blank: %s", got)
	}
}

func TestSanitize_TransformerNilRemovesNode(t *testing.T) {
	p := htmlsanitizer.DefaultPolicy()
	p.Transformers = []htmlsanitizer.Transformer{
		func(n *html.Node) *html.Node {
			if n.Type == html.ElementNode && n.Data == "b" {
				return nil
			}
			return n
		},
	}
	input := `<p><b>remove me</b> keep</p>`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "remove me") {
		t.Errorf("transformer returned nil so node should be gone: %s", got)
	}
}

func TestSanitize_Linkify(t *testing.T) {
	p := htmlsanitizer.DefaultPolicy()
	p.Linkify = true
	input := `Visit https://example.com for details`
	got, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `<a href="https://example.com"`) {
		t.Errorf("linkify should create anchor: %s", got)
	}
}

func TestStripTags(t *testing.T) {
	input := `<p>Hello <b>world</b></p>`
	got, err := htmlsanitizer.StripTags(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "<") {
		t.Errorf("StripTags left HTML: %s", got)
	}
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "world") {
		t.Errorf("StripTags lost text: %s", got)
	}
}

func TestSanitizeReader(t *testing.T) {
	input := `<b>hello</b><script>bad</script>`
	r := strings.NewReader(input)
	got, err := htmlsanitizer.SanitizeReader(r, htmlsanitizer.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "script") {
		t.Errorf("SanitizeReader should strip script: %s", got)
	}
}

func TestSetGetRemoveAttr(t *testing.T) {
	n := &html.Node{Type: html.ElementNode, Data: "a"}
	htmlsanitizer.SetAttr(n, "href", "https://example.com")
	if v := htmlsanitizer.GetAttr(n, "href"); v != "https://example.com" {
		t.Errorf("GetAttr got %q want https://example.com", v)
	}
	htmlsanitizer.SetAttr(n, "href", "https://other.com")
	if v := htmlsanitizer.GetAttr(n, "href"); v != "https://other.com" {
		t.Errorf("SetAttr update got %q", v)
	}
	htmlsanitizer.RemoveAttr(n, "href")
	if v := htmlsanitizer.GetAttr(n, "href"); v != "" {
		t.Errorf("RemoveAttr should leave empty, got %q", v)
	}
}

func TestDefaultPolicy_NotNil(t *testing.T) {
	p := htmlsanitizer.DefaultPolicy()
	if p == nil {
		t.Fatal("DefaultPolicy returned nil")
	}
}

func TestStrictPolicy_StripsDivs(t *testing.T) {
	input := `<b>ok</b><div>gone</div>`
	got, err := htmlsanitizer.Sanitize(input, htmlsanitizer.StrictPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "div") {
		t.Errorf("StrictPolicy should strip div: %s", got)
	}
	if !strings.Contains(got, "<b>ok</b>") {
		t.Errorf("StrictPolicy should keep b: %s", got)
	}
}

func BenchmarkSanitize(b *testing.B) {
	input := strings.Repeat(`<p>Hello <b>world</b> <script>bad()</script> <a href="http://x.com">link</a></p>`, 100)
	p := htmlsanitizer.DefaultPolicy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = htmlsanitizer.Sanitize(input, p)
	}
}
