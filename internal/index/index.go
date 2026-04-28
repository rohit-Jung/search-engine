// Package index - has the inverted index datastructure
package index

type (
	InvertedIndex = map[string][]Posting
	ForwardIndex  = map[string]map[string]int // docID -> term -> count
)

type Posting struct {
	CVEID    string
	TermFreq int // how many times term appears in this CVE
}
