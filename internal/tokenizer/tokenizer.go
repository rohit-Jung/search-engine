// Package tokenizer - exposes a function to tokenize
package tokenizer

import "strings"

var stopwords = map[string]bool{
	"a":   true,
	"an":  true,
	"the": true,
}

func Tokenize(doc string) []string {
	// lowercasing
	doc = strings.ToLower(doc)

	// TODO: currently it's spliting on whitespace only
	parts := strings.Split(doc, " ")

	var tokens []string
	for _, w := range parts {
		// removal of stop words
		if stopwords[w] {
			continue
		}

		// cleanup puncations and all

		// TODO: stem the words
		tokens = append(tokens, w)
	}

	return tokens
}
