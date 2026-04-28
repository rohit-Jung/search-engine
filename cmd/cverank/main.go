package main

import (
	"encoding/json"
	"log"
	"sort"

	"github.com/rohit-Jung/search-engine/config"
	nvd "github.com/rohit-Jung/search-engine/internal/fetcher"
	"github.com/rohit-Jung/search-engine/internal/graph"
	"github.com/rohit-Jung/search-engine/internal/parser"
	"github.com/rohit-Jung/search-engine/internal/ranking"
	"github.com/rohit-Jung/search-engine/internal/tokenizer"
)

type kv struct {
	id    string
	score float64
}

func main() {
	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Error while reading env", err)
	}

	corpus := nvd.GetEntireCorpus(config.Nvd.APIKey)

	// 1. build tf
	tf := ranking.NewTFIndex()
	for _, cve := range corpus {
		if err := tf.Add(cve); err != nil {
			continue
		}
	}

	// 2. build idf
	idf := ranking.BuildIDF(tf.TermFreqs)

	// 3. build inverted index
	inverted := ranking.BuildInverted(tf.TermFreqs)

	// 4. build pagerankc
	g := graph.BuildGraph(corpus)    // CPE → adjacency list
	prScores := graph.RunPageRank(g) // map[cve_id]float64

	// 4. query
	query := "openssl"
	queryTerms := tokenizer.Tokenize(query)

	// 5. get bm25scores for query
	bm25scores := ranking.BM25Score(queryTerms, inverted, tf, idf)

	// make a cvss map
	cvssMap := make(map[string]float64)
	for _, cve := range corpus {
		cvssMap[cve.ID] = cve.GetCVSSScore() / 10.0 // normalise it
	}

	// 6. get hybridScores
	scores := ranking.HybridRankin(bm25scores, prScores, cvssMap, corpus)

	// 7. extract top 5
	results := getTopN(5, scores, bm25scores, prScores, cvssMap, corpus)

	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(b))
}

func getTopN(n int,
	scores map[string]float64,
	bm25Scores map[string]float64,
	prScores map[string]float64,
	cvssMap map[string]float64,
	corpus []parser.CVE,
) []map[string]any {
	var list []kv
	for id, score := range scores {
		list = append(list, kv{id: id, score: score})
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].score > list[j].score
	})

	docMap := make(map[string]parser.CVE)
	for _, c := range corpus {
		docMap[c.ID] = c
	}

	top := min(len(list), n)
	var results []map[string]any

	for i := range top {
		id := list[i].id

		desc := ""
		if c, ok := docMap[id]; ok && len(c.Descriptions) > 0 {
			desc = c.Descriptions[0].Value
		}

		results = append(results, map[string]any{
			"cve_id":      id,
			"cvssScore":   cvssMap[id],
			"bm25":        bm25Scores[id],
			"pagerank":    prScores[id],
			"final_score": list[i].score,
			"description": desc,
		})
	}

	return results
}
