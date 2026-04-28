// Package ranking  -
package ranking

import (
	"maps"

	"github.com/rohit-Jung/search-engine/internal/index"
)

func SumMap(m map[string]int) int {
	values := maps.Values(m)
	var sum int
	for v := range values {
		sum += v
	}
	return sum
}

func BM25Score(
	queryTerms []string,
	inverted index.InvertedIndex,
	tf *TFIndex,
	idf *IDFIndex,
) map[string]float64 {
	scores := make(map[string]float64)

	k1 := 1.5
	b := 0.75

	// calculate the avg doc length
	avgdl := AvgDocLength(tf.DocsLen)

	for _, term := range queryTerms {
		postings, ok := inverted[term]
		if !ok {
			continue
		}

		idfScore := idf.scores[term]

		for _, posting := range postings {
			docID := posting.CVEID
			tfVal := float64(posting.TermFreq)
			dl := float64(tf.DocsLen[docID])

			// formula BM25
			score := idfScore *
				((tfVal * (k1 + 1)) /
					(tfVal + k1*(1-b+b*(dl/avgdl))))

			scores[docID] += score
		}
	}

	return scores
}
