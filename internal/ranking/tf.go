package ranking

import (
	"fmt"

	"github.com/rohit-Jung/search-engine/internal/index"
	"github.com/rohit-Jung/search-engine/internal/parser"
	"github.com/rohit-Jung/search-engine/internal/tokenizer"
)

type TFIndex struct {
	TermFreqs index.ForwardIndex // -> ForwardIndex - docId - (term - count in that doc)
	DocsLen   map[string]int     // docIdentifier -> docLength
}

func (tf *TFIndex) Add(cve parser.CVE) error {
	if !cve.ShouldIndex() {
		return fmt.Errorf("this shouldn't be indexed")
	}

	termFreqs := make(map[string]int)
	tokenizer.TermFreqToken(cve.Descriptions[0].Value, termFreqs)

	tf.TermFreqs[cve.ID] = termFreqs
	tf.DocsLen[cve.ID] = len(cve.Descriptions[0].Value)

	return nil
}

func AvgDocLength(docsLength map[string]int) float64 {
	var total int
	for _, l := range docsLength {
		total += l
	}
	return float64(total) / float64(len(docsLength))
}

func NewTFIndex() *TFIndex {
	return &TFIndex{
		TermFreqs: make(index.ForwardIndex),
		DocsLen:   make(map[string]int),
	}
}
