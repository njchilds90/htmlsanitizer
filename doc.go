// Package htmlsanitizer provides a fast, policy-driven HTML sanitizer
// for Go applications.
//
// # Overview
//
// htmlsanitizer parses an HTML string (or io.Reader) using the
// standard golang.org/x/net/html tokenizer, walks the resulting node
// tree, and produces a new HTML string that contains only the tags,
// attributes, and URL schemes permitted by a [Policy].
//
// # Policies
//
// A [Policy] controls:
//   - Which element tags are allowed ([Policy.AllowedTags])
//   - Which attributes are allowed per tag ([Policy.AllowedAttributes])
//   - Which URL schemes are allowed in href/src/action ([Policy.AllowedSchemes])
//   - Whether disallowed tags are stripped (removed with children) or escaped ([Policy.StripDisallowed])
//   - Zero or more [Transformer] callbacks that can mutate allowed nodes
//   - Whether plain-text URLs in text nodes become clickable links ([Policy.Linkify])
//   - A maximum DOM nesting depth ([Policy.MaxDepth])
//
// Two built-in policies are provided:
//   - [DefaultPolicy] — a permissive but safe policy covering common
//     content tags. Good starting point for blog posts, articles, etc.
//   - [StrictPolicy] — a minimal policy allowing only basic inline
//     formatting with no attributes. Good for comment sections.
//
// # Security
//
// htmlsanitizer defends against common XSS vectors including:
//   - Script injection via <script> tags
//   - Event handler attributes (onclick, onerror, etc.)
//   - javascript: and data: URL schemes (including entity-encoded forms)
//   - CSS expression injection via style attributes
//
// It does NOT provide a Content Security Policy header; pair with
// proper HTTP headers for defence in depth.
//
// # Thread Safety
//
// Sanitize and StripTags are safe for concurrent use. Policy structs
// should not be mutated after first use.
//
// # Example
//
//	p := htmlsanitizer.DefaultPolicy()
//	clean, err := htmlsanitizer.Sanitize(userInput, p)
package htmlsanitizer
