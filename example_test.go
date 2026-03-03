package htmlsanitizer_test

import (
	"fmt"

	"github.com/njchilds90/htmlsanitizer"
	"golang.org/x/net/html"
)

func ExampleSanitize() {
	input := `<b>Hello</b> <script>alert('xss')</script>`
	clean, err := htmlsanitizer.Sanitize(input, htmlsanitizer.DefaultPolicy())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(clean)
	// Output: <b>Hello</b>
}

func ExampleStripTags() {
	input := `<p>Hello <b>world</b></p>`
	text, err := htmlsanitizer.StripTags(input)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(text)
	// Output: Hello world
}

func ExampleSanitize_customPolicy() {
	p := &htmlsanitizer.Policy{
		AllowedTags: []string{"b", "i"},
		AllowedAttributes: map[string][]string{},
		AllowedSchemes:  []string{"https"},
		StripDisallowed: true,
	}
	input := `<b>bold</b> <div>stripped</div>`
	clean, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(clean)
	// Output: <b>bold</b>
}

func ExampleSanitize_transformer() {
	p := htmlsanitizer.DefaultPolicy()
	p.Transformers = []htmlsanitizer.Transformer{
		func(n *html.Node) *html.Node {
			if n.Type == html.ElementNode && n.Data == "a" {
				htmlsanitizer.SetAttr(n, "target", "_blank")
			}
			return n
		},
	}
	input := `<a href="https://example.com">link</a>`
	clean, err := htmlsanitizer.Sanitize(input, p)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(clean)
	// Output: <a href="https://example.com" target="_blank">link</a>
}
