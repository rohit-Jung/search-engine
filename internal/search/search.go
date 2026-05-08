package search

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	nvd "github.com/rohit-Jung/search-engine/internal/fetcher"
	"github.com/rohit-Jung/search-engine/internal/graph"
	"github.com/rohit-Jung/search-engine/internal/index"
	"github.com/rohit-Jung/search-engine/internal/parser"
	"github.com/rohit-Jung/search-engine/internal/ranking"
	"github.com/rohit-Jung/search-engine/internal/tokenizer"
)

type Result struct {
	ID           string  `json:"id"`
	Library      string  `json:"library"`
	Vendor       string  `json:"vendor"`
	Version      string  `json:"version"`
	CVSS         float64 `json:"cvss"`
	Severity     string  `json:"severity"`
	CWE          string  `json:"cwe"`
	CWEName      string  `json:"cweName"`
	Description  string  `json:"description"`
	Published    string  `json:"published"`
	AttackVector string  `json:"attackVector"`
	PageRank     float64 `json:"pageRankScore"`

	// Keep ranking internals available for debugging, but UI does not need them.
	RankScore float64 `json:"rankScore"`
}

// Engine caches the corpus and derived indexes in memory.
// It is safe for concurrent reads after construction.
type Engine struct {
	corpus   []parser.CVE
	docMap   map[string]parser.CVE
	tf       *ranking.TFIndex
	idf      *ranking.IDFIndex
	inverted index.InvertedIndex
	prScores map[string]float64
	cvssNorm map[string]float64
	cvssRaw  map[string]float64
	builtAt  time.Time
	corpusN  int
	source   string
}

type BuildOptions struct {
	// If empty, uses cached JSON under ./data/data-*.json.
	// If "nvd", uses live fetching via existing fetcher (not recommended for API startup).
	Source string
	APIKey string
}

func Build(opts BuildOptions) (*Engine, error) {
	corpus, err := loadCorpus(opts)
	if err != nil {
		return nil, err
	}
	if len(corpus) == 0 {
		return nil, fmt.Errorf("empty corpus")
	}

	tf := ranking.NewTFIndex()
	for _, cve := range corpus {
		_ = tf.Add(cve) // Add does filtering; skip errors
	}

	idf := ranking.BuildIDF(tf.TermFreqs)
	inverted := ranking.BuildInverted(tf.TermFreqs)

	g := graph.BuildGraph(corpus)
	prScores := graph.RunPageRank(g)

	cvssNorm := make(map[string]float64, len(corpus))
	cvssRaw := make(map[string]float64, len(corpus))
	docMap := make(map[string]parser.CVE, len(corpus))
	for _, cve := range corpus {
		docMap[cve.ID] = cve
		raw := cve.GetCVSSScore()
		cvssRaw[cve.ID] = raw
		cvssNorm[cve.ID] = raw / 10.0
	}

	return &Engine{
		corpus:   corpus,
		docMap:   docMap,
		tf:       tf,
		idf:      idf,
		inverted: inverted,
		prScores: prScores,
		cvssNorm: cvssNorm,
		cvssRaw:  cvssRaw,
		builtAt:  time.Now(),
		corpusN:  len(corpus),
		source:   opts.Source,
	}, nil
}

func (e *Engine) Meta() map[string]any {
	return map[string]any{
		"built_at":  e.builtAt.Format(time.RFC3339),
		"corpus_n":  e.corpusN,
		"source":    e.source,
		"idf_terms": e.idf.TermCount(),
	}
}

type SearchOptions struct {
	Library     string
	TopN        int
	MinSeverity string // LOW|MEDIUM|HIGH|CRITICAL
}

func (e *Engine) Search(opts SearchOptions) ([]Result, map[string]any) {
	topN := opts.TopN
	query := strings.TrimSpace(opts.Library)
	if topN <= 0 {
		topN = 10
	}
	if topN > 100 {
		topN = 100
	}
	minCVSS := minCVSSForSeverity(opts.MinSeverity)

	start := time.Now()
	queryTerms := tokenizer.Tokenize(query)
	bm25scores := ranking.BM25Score(queryTerms, e.inverted, e.tf, e.idf)
	scores := ranking.HybridRankin(bm25scores, e.prScores, e.cvssNorm, e.corpus)

	// Sort by final score.
	type kv struct {
		id    string
		score float64
	}
	list := make([]kv, 0, len(scores))
	for id, s := range scores {
		if minCVSS > 0 {
			if e.cvssRaw[id] < minCVSS {
				continue
			}
		}
		list = append(list, kv{id: id, score: s})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].score > list[j].score })

	n := topN
	if len(list) < n {
		n = len(list)
	}
	out := make([]Result, 0, n)
	for i := 0; i < n; i++ {
		id := list[i].id
		c, ok := e.docMap[id]
		if !ok {
			continue
		}

		desc := ""
		if len(c.Descriptions) > 0 {
			desc = c.Descriptions[0].Value
		}
		vendor, product, version := firstCPEDetails(c)
		cweID, cweName := c.GetCWE()
		published := ""
		if !time.Time(c.Published.Time).IsZero() {
			published = time.Time(c.Published.Time).Format(time.RFC3339)
		}

		out = append(out, Result{
			ID:           id,
			Library:      product,
			Vendor:       vendor,
			Version:      version,
			CVSS:         e.cvssRaw[id],
			Severity:     severityForCVSS(e.cvssRaw[id]),
			CWE:          cweID,
			CWEName:      cweName,
			Description:  desc,
			Published:    published,
			AttackVector: c.GetAttackVector(),
			PageRank:     e.prScores[id],
			RankScore:    list[i].score,
		})
	}

	meta := map[string]any{
		"library":        query,
		"severity":       strings.ToUpper(strings.TrimSpace(opts.MinSeverity)),
		"min_cvss":       minCVSS,
		"query_terms":    queryTerms,
		"top":            topN,
		"elapsed_ms":     time.Since(start).Milliseconds(),
		"engine_builtAt": e.builtAt.Format(time.RFC3339),
	}
	return out, meta
}

func minCVSSForSeverity(sev string) float64 {
	s := strings.ToUpper(strings.TrimSpace(sev))
	switch s {
	case "LOW":
		return 0.1
	case "MEDIUM":
		return 4.0
	case "HIGH":
		return 7.0
	case "CRITICAL":
		return 9.0
	default:
		return 0
	}
}

func severityForCVSS(cvss float64) string {
	if cvss >= 9.0 {
		return "CRITICAL"
	}
	if cvss >= 7.0 {
		return "HIGH"
	}
	if cvss >= 4.0 {
		return "MEDIUM"
	}
	if cvss > 0 {
		return "LOW"
	}
	return "UNKNOWN"
}

func firstCPEDetails(c parser.CVE) (vendor, product, version string) {
	for _, conf := range c.Configurations {
		for _, node := range conf.Nodes {
			for _, cpe := range node.CPEMatch {
				d := cpe.GetCPEDetails()
				if d == nil {
					continue
				}
				if d.Product == "" {
					continue
				}
				return d.Vendor, d.Product, d.Version
			}
		}
	}
	return "", "", ""
}

func loadCorpus(opts BuildOptions) ([]parser.CVE, error) {
	if strings.EqualFold(opts.Source, "nvd") {
		// Live fetch + cache behavior is already in fetcher.
		return nvd.GetEntireCorpus(opts.APIKey), nil
	}

	// Default: load cached pages from ./data/data-*.json.
	files, err := filepath.Glob("./data/data-*.json")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no cached NVD pages found under ./data (expected data-*.json)")
	}
	sort.Strings(files)

	// Only need vulnerabilities[].cve projection; parser types already match.
	type nvdPage struct {
		Vulnerabilities []parser.Vulnerability `json:"vulnerabilities"`
	}

	corpus := make([]parser.CVE, 0, len(files)*100)
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var page nvdPage
		if err := json.Unmarshal(b, &page); err != nil {
			continue
		}
		for _, v := range page.Vulnerabilities {
			corpus = append(corpus, v.CVE)
		}
	}
	return corpus, nil
}
