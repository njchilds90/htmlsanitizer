// Package htmlsanitizer provides a fast, flexible HTML sanitizer.
// It allows you to define a Policy specifying which HTML tags and
// attributes are permitted, how URLs are validated, and how matched
// nodes are transformed. It is inspired by Python's bleach and
// Node.js's sanitize-html.
//
// Basic usage:
//
//	clean, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
package htmlsanitizer

import (
	"bytes"
	"io"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Transformer is a function that receives an allowed HTML node and may
// mutate it in place (e.g., adding or removing attributes). Returning
// nil removes the node from the output entirely.
type Transformer func(n *html.Node) *html.Node

// Policy defines what HTML is considered safe.
type Policy struct {
	// AllowedTags is the list of tag names that are kept in output.
	// All other element nodes are either stripped (removed entirely,
	// children promoted) or escaped, depending on StripDisallowed.
	AllowedTags []string

	// AllowedAttributes maps tag names to the list of attribute names
	// that are kept on that tag. Use "*" as a key to allow attributes
	// on every tag.
	AllowedAttributes map[string][]string

	// AllowedSchemes lists the URL schemes (e.g. "http", "https",
	// "mailto") permitted in href and src attributes. Any URL whose
	// scheme is not in this list is removed from the attribute.
	AllowedSchemes []string

	// StripDisallowed controls behavior for disallowed element nodes.
	// When true the element and all its descendants are removed.
	// When false (default) the element tags are escaped to plain text
	// but descendants are still walked.
	StripDisallowed bool

	// Transformers is an optional slice of Transformer functions applied
	// in order to every allowed element node after attribute filtering.
	Transformers []Transformer

	// Linkify converts plain-text URLs found in text nodes into <a>
	// elements pointing to those URLs.
	Linkify bool

	// MaxDepth limits how deeply nested elements may be. Nodes at
	// a depth greater than MaxDepth are stripped (children promoted).
	// Zero means unlimited.
	MaxDepth int
}

// urlRegexp matches http/https URLs inside plain text.
var urlRegexp = regexp.MustCompile(`https?://[^\s<>"]+[^\s<>".,;:!?)\]]`)

// DefaultPolicy returns a Policy that allows a common safe subset of
// HTML used in content — headings, paragraphs, formatting, lists,
// links, images, code, blockquotes — while rejecting script, style,
// and other dangerous tags. Links and image sources must use http,
// https, or mailto.
func DefaultPolicy() *Policy {
	return &Policy{
		AllowedTags: []string{
			"h1", "h2", "h3", "h4", "h5", "h6",
			"p", "br", "hr",
			"b", "i", "em", "strong", "u", "s", "strike", "del", "ins",
			"a", "img",
			"ul", "ol", "li",
			"table", "thead", "tbody", "tfoot", "tr", "th", "td",
			"code", "pre", "kbd", "samp",
			"blockquote", "cite", "q",
			"figure", "figcaption",
			"div", "span", "section", "article", "header", "footer",
			"details", "summary",
			"abbr", "acronym", "address",
			"sup", "sub",
		},
		AllowedAttributes: map[string][]string{
			"a":          {"href", "title", "target", "rel"},
			"img":        {"src", "alt", "title", "width", "height", "loading"},
			"td":         {"colspan", "rowspan", "align", "valign"},
			"th":         {"colspan", "rowspan", "align", "valign", "scope"},
			"blockquote": {"cite"},
			"q":          {"cite"},
			"abbr":       {"title"},
			"acronym":    {"title"},
			"*":          {"id", "class", "lang", "dir"},
		},
		AllowedSchemes:  []string{"http", "https", "mailto"},
		StripDisallowed: false,
	}
}

// StrictPolicy returns a Policy that allows only the most basic inline
// formatting tags with no attributes at all — suitable for comment
// sections and user-generated content where you want minimal markup.
func StrictPolicy() *Policy {
	return &Policy{
		AllowedTags:     []string{"b", "i", "em", "strong", "br", "p", "ul", "ol", "li"},
		AllowedAttributes: map[string][]string{},
		AllowedSchemes:  []string{"https"},
		StripDisallowed: true,
	}
}

// Sanitize parses htmlStr, applies p, and returns the sanitized HTML.
// If p is nil, DefaultPolicy is used.
func Sanitize(htmlStr string, p *Policy) (string, error) {
	return SanitizeReader(strings.NewReader(htmlStr), p)
}

// SanitizeReader reads HTML from r, applies p, and returns the
// sanitized HTML string.
func SanitizeReader(r io.Reader, p *Policy) (string, error) {
	if p == nil {
		p = DefaultPolicy()
	}

	doc, err := html.Parse(r)
	if err != nil {
		return "", err
	}

	// Build lookup sets for O(1) access.
	allowedTags := sliceToSet(p.AllowedTags)
	allowedSchemes := sliceToSet(p.AllowedSchemes)

	var buf bytes.Buffer
	var walk func(n *html.Node, depth int)

	walk = func(n *html.Node, depth int) {
		switch n.Type {
		case html.TextNode:
			if p.Linkify {
				writeLinkedText(&buf, n.Data)
			} else {
				buf.WriteString(html.EscapeString(n.Data))
			}

		case html.ElementNode:
			tag := strings.ToLower(n.Data)
			tooDeep := p.MaxDepth > 0 && depth > p.MaxDepth
			allowed := allowedTags[tag] && !tooDeep

			if allowed {
				// Filter attributes.
				n.Attr = filterAttrs(n.Attr, tag, p.AllowedAttributes, allowedSchemes)

				// Run transformers.
				for _, t := range p.Transformers {
					if n = t(n); n == nil {
						return
					}
				}

				buf.WriteByte('<')
				buf.WriteString(tag)
				for _, a := range n.Attr {
					buf.WriteByte(' ')
					buf.WriteString(a.Key)
					buf.WriteString(`="`)
					buf.WriteString(html.EscapeString(a.Val))
					buf.WriteByte('"')
				}
				if isVoidElement(tag) {
					buf.WriteString(" />")
					return
				}
				buf.WriteByte('>')
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, depth+1)
				}
				buf.WriteString("</")
				buf.WriteString(tag)
				buf.WriteByte('>')
			} else {
				if p.StripDisallowed {
					return // drop node and all descendants
				}
				// Escape the open tag, recurse into children, escape close tag.
				buf.WriteString(html.EscapeString(renderOpenTag(n)))
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, depth+1)
				}
				if !isVoidElement(tag) {
					buf.WriteString(html.EscapeString("</"+tag+">"))
				}
			}

		case html.DocumentNode:
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, depth)
			}

		case html.DoctypeNode:
			// skip

		case html.CommentNode:
			// strip comments

		default:
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c, depth)
			}
		}
	}

	// html.Parse wraps content in <html><head><body>; find body.
	body := findBody(doc)
	if body != nil {
		for c := body.FirstChild; c != nil; c = c.NextSibling {
			walk(c, 1)
		}
	} else {
		walk(doc, 0)
	}

	return buf.String(), nil
}

// StripTags removes all HTML tags and returns plain text. Entity
// references are decoded.
func StripTags(htmlStr string) (string, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	body := findBody(doc)
	if body != nil {
		walk(body)
	} else {
		walk(doc)
	}
	return buf.String(), nil
}

// SetAttr sets (or adds) the attribute key=val on node n. It is
// intended for use inside Transformer functions.
func SetAttr(n *html.Node, key, val string) {
	for i, a := range n.Attr {
		if a.Key == key {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: key, Val: val})
}

// GetAttr returns the value of the named attribute on n, or "" if not
// present.
func GetAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// RemoveAttr removes the named attribute from n if present.
func RemoveAttr(n *html.Node, key string) {
	attrs := n.Attr[:0]
	for _, a := range n.Attr {
		if a.Key != key {
			attrs = append(attrs, a)
		}
	}
	n.Attr = attrs
}

// --- helpers ---------------------------------------------------------

func filterAttrs(attrs []html.Attribute, tag string, allowed map[string][]string, schemes map[string]bool) []html.Attribute {
	out := attrs[:0]
	for _, a := range attrs {
		tagAllowed := attrAllowed(a.Key, tag, allowed)
		if !tagAllowed {
			continue
		}
		if a.Key == "href" || a.Key == "src" || a.Key == "action" {
			if !schemeAllowed(a.Val, schemes) {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

func attrAllowed(attr, tag string, allowed map[string][]string) bool {
	if list, ok := allowed["*"]; ok {
		for _, a := range list {
			if a == attr {
				return true
			}
		}
	}
	if list, ok := allowed[tag]; ok {
		for _, a := range list {
			if a == attr {
				return true
			}
		}
	}
	return false
}

func schemeAllowed(raw string, schemes map[string]bool) bool {
	raw = strings.TrimSpace(raw)
	// Decode HTML entities to prevent &#106;avascript: bypasses.
	decoded := htmlDecodeMinimal(raw)
	decoded = strings.ToLower(strings.TrimSpace(decoded))

	// Strip zero-width / control chars that can confuse parsers.
	decoded = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, decoded)

	u, err := url.Parse(decoded)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		// Relative URL — allow.
		return true
	}
	return schemes[scheme]
}

// htmlDecodeMinimal decodes a few common entity tricks used to smuggle
// schemes (&#x6A; etc.) without pulling in a full entity decoder.
func htmlDecodeMinimal(s string) string {
	var buf bytes.Buffer
	r := strings.NewReader(s)
	// Use golang.org/x/net/html tokenizer trick: wrap in an attribute
	// and let the parser decode it.
	fragment := "<a href=\"" + s + "\">"
	doc, err := html.Parse(strings.NewReader(fragment))
	if err != nil {
		return s
	}
	var found string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					found = a.Val
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	_ = buf
	_ = r
	if found != "" {
		return found
	}
	return s
}

func sliceToSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[strings.ToLower(v)] = true
	}
	return m
}

func isVoidElement(tag string) bool {
	switch tag {
	case "area", "base", "br", "col", "embed", "hr", "img", "input",
		"link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}

func renderOpenTag(n *html.Node) string {
	var sb strings.Builder
	sb.WriteByte('<')
	sb.WriteString(n.Data)
	for _, a := range n.Attr {
		sb.WriteByte(' ')
		sb.WriteString(a.Key)
		sb.WriteString(`="`)
		sb.WriteString(a.Val)
		sb.WriteByte('"')
	}
	sb.WriteByte('>')
	return sb.String()
}

func findBody(doc *html.Node) *html.Node {
	var find func(*html.Node) *html.Node
	find = func(n *html.Node) *html.Node {
		if n.Type == html.ElementNode && n.Data == "body" {
			return n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if r := find(c); r != nil {
				return r
			}
		}
		return nil
	}
	return find(doc)
}

func writeLinkedText(w *bytes.Buffer, text string) {
	last := 0
	matches := urlRegexp.FindAllStringIndex(text, -1)
	for _, m := range matches {
		w.WriteString(html.EscapeString(text[last:m[0]]))
		rawURL := text[m[0]:m[1]]
		w.WriteString(`<a href="`)
		w.WriteString(html.EscapeString(rawURL))
		w.WriteString(`" rel="noopener noreferrer">`)
		w.WriteString(html.EscapeString(rawURL))
		w.WriteString(`</a>`)
		last = m[1]
	}
	w.WriteString(html.EscapeString(text[last:]))
}
