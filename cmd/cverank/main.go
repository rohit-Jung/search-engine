package main

import (
	"flag"
	"log"
	"sort"
	"time"

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
	var (
		query = flag.String("query", "openssl", "query string")
		topN  = flag.Int("top", 5, "number of results")
	)
	flag.Parse()

	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Error while reading env", err)
	}

	start := time.Now()
	corpus := nvd.GetEntireCorpus(config.Nvd.APIKey)
	log.Printf("corpus loaded n=%d elapsed=%s", len(corpus), time.Since(start).Truncate(time.Millisecond))

	// 1. build tf
	start = time.Now()
	tf := ranking.NewTFIndex()
	for _, cve := range corpus {
		if err := tf.Add(cve); err != nil {
			continue
		}
	}
	log.Printf("tf built docs=%d elapsed=%s", len(tf.TermFreqs), time.Since(start).Truncate(time.Millisecond))

	// 2. build idf
	start = time.Now()
	idf := ranking.BuildIDF(tf.TermFreqs)
	log.Printf("idf built terms=%d elapsed=%s", idf.TermCount(), time.Since(start).Truncate(time.Millisecond))

	// 3. build inverted index
	start = time.Now()
	inverted := ranking.BuildInverted(tf.TermFreqs)
	log.Printf("inverted built terms=%d elapsed=%s", len(inverted), time.Since(start).Truncate(time.Millisecond))

	// 4. build pagerankc
	start = time.Now()
	g := graph.BuildGraph(corpus)    // CPE → adjacency list
	prScores := graph.RunPageRank(g) // map[cve_id]float64
	log.Printf("pagerank built nodes=%d elapsed=%s", len(prScores), time.Since(start).Truncate(time.Millisecond))

	// 4. query
	queryTerms := tokenizer.Tokenize(*query)

	// 5. get bm25scores for query
	start = time.Now()
	bm25scores := ranking.BM25Score(queryTerms, inverted, tf, idf)
	log.Printf("bm25 scored docs=%d elapsed=%s", len(bm25scores), time.Since(start).Truncate(time.Millisecond))

	// make a cvss map
	cvssMap := make(map[string]float64)
	for _, cve := range corpus {
		cvssMap[cve.ID] = cve.GetCVSSScore() / 10.0 // normalise it
	}

	// 6. get hybridScores
	start = time.Now()
	scores := ranking.HybridRankin(bm25scores, prScores, cvssMap, corpus)
	log.Printf("hybrid scored docs=%d elapsed=%s", len(scores), time.Since(start).Truncate(time.Millisecond))

	// 7. extract top 5
	getTopN(*topN, scores, bm25scores, prScores, cvssMap, corpus)

	// b, err := json.MarshalIndent(results, "", "  ")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// log.Println(string(b))
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
