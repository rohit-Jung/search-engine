// Package tokenizer - exposes a function to tokenize
package tokenizer

import (
	"strings"
	"unicode"
)

var stopwords = map[string]bool{
	"a":   true,
	"an":  true,
	"the": true,
}

func Tokenize(doc string) []string {
	// lowercasing
	doc = strings.ToLower(doc)

	// NAIVE: currently it's spliting on whitespace only
	// parts := strings.Split(doc, " ")

	// split on anything thats non alphanumeric, removes puncations
	words := strings.FieldsFunc(doc, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	var tokens []string
	for _, w := range words {
		// removal of stop words
		if stopwords[w] {
			continue
		}

		// this may be a noise
		if len(w) < 3 {
			continue
		}

		// cleanup puncations and all
		stemmed := Stem(w)
		tokens = append(tokens, stemmed)
	}

	return tokens
}

// TermFreqToken TF calculation
func TermFreqToken(text string, termFreqMap map[string]int) map[string]int {
	tokens := Tokenize(text)
	for _, w := range tokens {
		// cause zero value of int is 0 so
		termFreqMap[w]++
	}
	return termFreqMap
}
