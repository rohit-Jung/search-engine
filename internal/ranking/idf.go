// Package ranking  -
package ranking

import (
	"math"

	"github.com/rohit-Jung/search-engine/internal/index"
)

type IDFIndex struct {
	docFreq   map[string]float64 // map[term] -> term count across corpus, you need this for IDF calc
	scores    map[string]float64 // map[term] -> idf score of each term
	totalDocs int                // length of corpus
}

func (i *IDFIndex) TermCount() int {
	if i == nil {
		return 0
	}
	return len(i.scores)
}

// BuildIDF - allDocs - docID -> (term -> count)
func BuildIDF(allDocs map[string]map[string]int) *IDFIndex {
	docFreq := make(map[string]float64)
	totalDocs := len(allDocs)

	// count document frequency
	for _, termMap := range allDocs {
		for term := range termMap {
			docFreq[term]++
		}
	}

	// compute idf
	scores := make(map[string]float64)
	for term, df := range docFreq {
		scores[term] = math.Log(float64(totalDocs) / float64(df))
	}

	return &IDFIndex{
		docFreq:   docFreq,
		scores:    scores,
		totalDocs: totalDocs,
	}
}

// BuildInverted
//
//	inverted := map[string][]Posting{
//		"buffer": {
//			{CVEID: "CVE-1", TermFreq: 2},
//		},
//		"overflow": {
//			{CVEID: "CVE-1", TermFreq: 1},
//			{CVEID: "CVE-2", TermFreq: 3},
//		},
//	}
func BuildInverted(forward index.ForwardIndex) index.InvertedIndex {
	inverted := make(index.InvertedIndex)

	for docID, termMap := range forward {
		for term, count := range termMap {
			inverted[term] = append(inverted[term], index.Posting{
				CVEID:    docID,
				TermFreq: count,
			})
		}
	}

	return inverted
}
