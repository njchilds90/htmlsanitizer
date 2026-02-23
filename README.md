# htmlsanitizer

[![Go Reference](https://pkg.go.dev/badge/github.com/njchilds90/htmlsanitizer.svg)](https://pkg.go.dev/github.com/njchilds90/htmlsanitizer)
[![Go Report Card](https://goreportcard.com/badge/github.com/njchilds90/htmlsanitizer)](https://goreportcard.com/report/github.com/njchilds90/htmlsanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A fast, flexible HTML sanitizer for Go. Strip unwanted tags and attributes, enforce allow-lists, rewrite URLs, and transform nodes — inspired by Python's [bleach](https://github.com/mozilla/bleach) and Node's [sanitize-html](https://github.com/apostrophecms/sanitize-html).

## Features

- ✅ Allow-list based tag and attribute filtering
- ✅ Strip or escape disallowed tags
- ✅ Per-tag attribute allow-lists
- ✅ URL sanitization (block `javascript:`, `data:` schemes)
- ✅ Custom node transformer functions
- ✅ Plain-text extraction (strip all HTML)
- ✅ Link auto-detection / linkification
- ✅ Configurable depth limiting
- ✅ Thread-safe, zero global state
- ✅ No CGO — pure Go

## Installation
```bash
go get github.com/njchilds90/htmlsanitizer
```

## Quick Start
```go
package main

import (
    "fmt"
    "github.com/njchilds90/htmlsanitizer"
)

func main() {
    input := `<b>Hello</b> <script>alert('xss')</script> <a href="javascript:void(0)">click</a>`

    clean, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
    if err != nil {
        panic(err)
    }
    fmt.Println(clean)
    // Output: <b>Hello</b>  <a>click</a>
}
```

## Usage

### Default Policy
```go
clean, err := htmlsanitizer.Sanitize(html, htmlsanitizer.DefaultPolicy())
```

The default policy allows common safe tags (`p`, `b`, `i`, `em`, `strong`, `a`, `ul`, `ol`, `li`, `br`, `code`, `pre`, `blockquote`) and strips `href` values with dangerous schemes.

### Custom Policy
```go
policy := &htmlsanitizer.Policy{
    AllowedTags: []string{"p", "b", "a", "img"},
    AllowedAttributes: map[string][]string{
        "a":   {"href", "title", "target"},
        "img": {"src", "alt", "width", "height"},
    },
    AllowedSchemes: []string{"http", "https", "mailto"},
    StripDisallowed: true, // remove tags entirely vs escaping them
}

clean, err := htmlsanitizer.Sanitize(input, policy)
```

### Strip All HTML (Plain Text)
```go
text, err := htmlsanitizer.StripTags(html)
```

### Custom Transformers
```go
policy := htmlsanitizer.DefaultPolicy()
policy.Transformers = []htmlsanitizer.Transformer{
    func(n *html.Node) *html.Node {
        // Force all links to open in a new tab
        if n.Type == html.ElementNode && n.Data == "a" {
            htmlsanitizer.SetAttr(n, "target", "_blank")
            htmlsanitizer.SetAttr(n, "rel", "noopener noreferrer")
        }
        return n
    },
}
```

### Linkify Plain Text URLs
```go
policy := htmlsanitizer.DefaultPolicy()
policy.Linkify = true

clean, err := htmlsanitizer.Sanitize("Visit https://example.com today", policy)
// Output: Visit <a href="https://example.com" rel="noopener noreferrer">https://example.com</a> today
```

### Depth Limiting
```go
policy := htmlsanitizer.DefaultPolicy()
policy.MaxDepth = 5 // strip nodes nested deeper than 5 levels
```

## API Reference

| Function | Description |
|---|---|
| `Sanitize(html string, p *Policy) (string, error)` | Sanitize HTML string with given policy |
| `SanitizeReader(r io.Reader, p *Policy) (string, error)` | Sanitize from an `io.Reader` |
| `StripTags(html string) (string, error)` | Remove all HTML, return plain text |
| `DefaultPolicy() *Policy` | Returns a safe, permissive default policy |
| `SetAttr(n *html.Node, key, val string)` | Helper to set attribute on a node |
| `GetAttr(n *html.Node, key string) string` | Helper to get attribute value from a node |

## Policy Fields

| Field | Type | Description |
|---|---|---|
| `AllowedTags` | `[]string` | Tags to keep (all others stripped/escaped) |
| `AllowedAttributes` | `map[string][]string` | Per-tag allowed attributes |
| `AllowedSchemes` | `[]string` | URL schemes allowed in href/src |
| `StripDisallowed` | `bool` | Strip vs HTML-escape disallowed tags |
| `Transformers` | `[]Transformer` | Functions to mutate allowed nodes |
| `Linkify` | `bool` | Auto-link URLs in text nodes |
| `MaxDepth` | `int` | Max nesting depth (0 = unlimited) |

## Comparison

| Feature | htmlsanitizer | bluemonday | goquery |
|---|---|---|---|
| Allow-list tags/attrs | ✅ | ✅ | ❌ |
| URL scheme filtering | ✅ | ✅ | ❌ |
| Node transformers | ✅ | ⚠️ limited | ✅ |
| Linkify | ✅ | ❌ | ❌ |
| Simple one-call API | ✅ | ❌ | ❌ |
| Depth limiting | ✅ | ❌ | ❌ |
| Plain text extract | ✅ | ❌ | ⚠️ |

## Contributing

Pull requests welcome. Please add tests for any new policy features.

## License

MIT — see [LICENSE](LICENSE)
