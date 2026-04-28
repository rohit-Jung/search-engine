// Package ranking  -
package ranking

import (
	"github.com/rohit-Jung/search-engine/internal"
	"github.com/rohit-Jung/search-engine/internal/parser"
)

const (
	weightBM25     = 0.4
	weightPageRank = 0.3
	weightCVSS     = 0.3
)

// HybridRankin - this takes into account CVSS, PageRank and BM25
func HybridRankin(
	bm25Scores map[string]float64,
	prScores map[string]float64,
	cvssMap map[string]float64,
	corpus []parser.CVE,
) map[string]float64 {
	bm25Norm := internal.NormaliseMap(bm25Scores)
	final := make(map[string]float64)

	for id, bm25 := range bm25Norm {
		pr := prScores[id]
		cvss := cvssMap[id]

		final[id] = (weightBM25 * bm25) + (weightPageRank * pr) + (weightCVSS * cvss)
	}

	return final
}
