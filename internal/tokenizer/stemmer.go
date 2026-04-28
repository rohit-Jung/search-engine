// Package tokenizer - stemmer
package tokenizer

import "strings"

// Stem simplified porter stemmer 
// ref: https://vijinimallawaarachchi.com/2017/05/09/porter-stemming-algorithm/
// stem reduces a word to its root form
func Stem(word string) string {
	if len(word) <= 2 {
		return word
	}

	// passes
	word = pass1a(word)
	word = pass1b(word)
	word = pass2(word)
	word = pass3(word)
	word = pass4(word)
	word = pass5(word)

	return word
}

// measure = number of VC sequences in stem
// V = vowel, C = consonant
// "tree" = 1, "trouble" = 2, "oat" = 1
func measure(s string) int {
	n := 0
	inVowel := false
	for i, c := range s {
		isV := isVowel(s, i)
		if isV && !inVowel {
			inVowel = true
		} else if !isV && inVowel {
			inVowel = false
			n++
		}
		_ = c
	}
	return n
}

func isVowel(s string, i int) bool {
	switch s[i] {
	case 'a', 'e', 'i', 'o', 'u':
		return true
	case 'y':
		return i > 0 && !isVowel(s, i-1) // y is vowel if preceded by consonant
	}
	return false
}

func containsVowel(s string) bool {
	for i := range s {
		if isVowel(s, i) {
			return true
		}
	}
	return false
}

func hasSuffix(s, suffix string) (string, bool) {
	if strings.HasSuffix(s, suffix) {
		// strip away the suffix
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// Pass 1a — plurals
func pass1a(word string) string {
	if stem, ok := hasSuffix(word, "sses"); ok {
		return stem + "ss"
	}
	if stem, ok := hasSuffix(word, "ies"); ok {
		return stem + "i"
	}
	if stem, ok := hasSuffix(word, "ss"); ok {
		return stem + "ss"
	}
	if stem, ok := hasSuffix(word, "s"); ok {
		return stem
	}
	return word
}

// Pass 1b — past tense and progressive
func pass1b(word string) string {
	if stem, ok := hasSuffix(word, "eed"); ok {
		if measure(stem) > 0 {
			return stem + "ee"
		}
		return word
	}

	if stem, ok := hasSuffix(word, "ed"); ok {
		if containsVowel(stem) {
			return pass1bHelper(stem)
		}
		return word
	}

	if stem, ok := hasSuffix(word, "ing"); ok {
		if containsVowel(stem) {
			return pass1bHelper(stem)
		}
		return word
	}

	return word
}

func pass1bHelper(stem string) string {
	// after removing ed/ing, apply these rules
	if strings.HasSuffix(stem, "at") ||
		strings.HasSuffix(stem, "bl") ||
		strings.HasSuffix(stem, "iz") {
		return stem + "e"
	}
	// double consonant — remove one
	last := stem[len(stem)-1]
	if len(stem) > 1 && stem[len(stem)-2] == last {
		switch last {
		case 'l', 's', 'z': // don't remove these doubles
		default:
			return stem[:len(stem)-1]
		}
	}
	return stem
}

// Pass 2 — common suffixes
func pass2(word string) string {
	rules := []struct{ suffix, replace string }{
		{"ational", "ate"},
		{"tional", "tion"},
		{"enci", "ence"},
		{"anci", "ance"},
		{"izer", "ize"},
		{"iser", "ise"},
		{"alli", "al"},
		{"entli", "ent"},
		{"eli", "e"},
		{"ousli", "ous"},
		{"ization", "ize"},
		{"isation", "ise"},
		{"ation", "ate"},
		{"ator", "ate"},
		{"alism", "al"},
		{"iveness", "ive"},
		{"fulness", "ful"},
		{"ousness", "ous"},
		{"aliti", "al"},
		{"iviti", "ive"},
		{"biliti", "ble"},
	}
	for _, r := range rules {
		if stem, ok := hasSuffix(word, r.suffix); ok {
			if measure(stem) > 0 {
				return stem + r.replace
			}
		}
	}
	return word
}

// Pass 3
func pass3(word string) string {
	rules := []struct{ suffix, replace string }{
		{"icate", "ic"},
		{"ative", ""},
		{"alize", "al"},
		{"alise", "al"},
		{"iciti", "ic"},
		{"ical", "ic"},
		{"ful", ""},
		{"ness", ""},
	}
	for _, r := range rules {
		if stem, ok := hasSuffix(word, r.suffix); ok {
			if measure(stem) > 0 {
				return stem + r.replace
			}
		}
	}
	return word
}

// Pass 4 — residual suffixes
func pass4(word string) string {
	suffixes := []string{
		"al", "ance", "ence", "er", "ic",
		"able", "ible", "ant", "ement", "ment",
		"ent", "ism", "ate", "iti", "ous",
		"ive", "ize", "ise",
	}
	for _, s := range suffixes {
		if stem, ok := hasSuffix(word, s); ok {
			if measure(stem) > 1 {
				return stem
			}
		}
	}
	// special: ion needs stem ending in s or t
	if stem, ok := hasSuffix(word, "ion"); ok {
		if measure(stem) > 1 && len(stem) > 0 {
			last := stem[len(stem)-1]
			if last == 's' || last == 't' {
				return stem
			}
		}
	}
	return word
}

// Pass 5 — final cleanup
func pass5(word string) string {
	if stem, ok := hasSuffix(word, "e"); ok {
		m := measure(stem)
		if m > 1 {
			return stem
		}
	}
	if strings.HasSuffix(word, "ll") && measure(word[:len(word)-1]) > 1 {
		return word[:len(word)-1]
	}
	return word
}
