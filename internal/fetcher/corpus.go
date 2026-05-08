package nvd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rohit-Jung/search-engine/internal/parser"
)

func GetCorpus(numCve int, pageSize int, apiKey string) []parser.CVE {
	var corpus []parser.CVE

	for i := 0; i < numCve; i += pageSize {
		filePath := fmt.Sprintf("./data/data-%v.json", i)
		_, err := os.Stat(filePath)

		var result parser.NVDResponse

		if err != nil {
			fetchRes, err := FetchAndWrite(strconv.Itoa(i), strconv.Itoa(pageSize), filePath, apiKey)
			if err != nil {
				log.Fatal("Error while fetching", err)
			}

			result = *fetchRes
		} else {
			contents, err := os.ReadFile(filePath)
			if err != nil {
				log.Printf("Couldn't read file %s: %v", filePath, err)
				continue
			}

			err = json.Unmarshal(contents, &result)
			if err != nil {
				log.Printf("Skipping invalid JSON in %s: %v", filePath, err)
				continue
			}

		}

		for j := 0; j < result.ResultsPerPage; j++ {
			corpus = append(corpus, result.Vulnerabilities[j].CVE)
		}
	}

	return corpus
}

func GetCorpusParallel(numCve int, pageSize int, apiKey string) []parser.CVE {
	type result struct {
		index int
		cves  []parser.CVE
	}

	numPages := (numCve + pageSize - 1) / pageSize
	results := make([]result, numPages)
	resultsCh := make(chan result, numPages)

	// num of request with and without api key differ so
	maxWorkers := 5
	rateLimitDelay := 700 * time.Millisecond
	if apiKey == "" {
		maxWorkers = 1
		rateLimitDelay = 6 * time.Second // NVD allows 5 req/30s without API key
	}
	sem := make(chan struct{}, maxWorkers)

	var wg sync.WaitGroup

	for i := 0; i < numCve; i += pageSize {
		wg.Add(1)
		i := i
		// go routine
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			// Rate limit: sleep between requests
			time.Sleep(rateLimitDelay)

			filePath := fmt.Sprintf("./data/data-%v.json", i)
			_, err := os.Stat(filePath)

			var nvdResult parser.NVDResponse

			if err != nil {
				fetchRes, err := FetchAndWrite(strconv.Itoa(i), strconv.Itoa(pageSize), filePath, apiKey)
				if err != nil {
					log.Fatal("Error while fetching", err)
				}

				nvdResult = *fetchRes
			} else {
				contents, err := os.ReadFile(filePath)
				if err != nil {
					log.Printf("Couldn't read file %s: %v", filePath, err)
					return
				}

				err = json.Unmarshal(contents, &nvdResult)
				if err != nil {
					log.Printf("Skipping invalid JSON in %s: %v", filePath, err)
					return
				}

			}

			var cves []parser.CVE
			for _, v := range nvdResult.Vulnerabilities {
				cves = append(cves, v.CVE)
			}
			resultsCh <- result{index: i, cves: cves}
		}()
	}

	// wait for all goRoutines to complete and close the channel
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// collect results — they arrive out of order, so sort after
	for r := range resultsCh {
		results[r.index/pageSize] = r
	}

	// flatten in original order
	var corpus []parser.CVE
	for _, r := range results {
		corpus = append(corpus, r.cves...)
	}

	return corpus
}

func GetEntireCorpus(apiKey string) []parser.CVE {
	const pageSize = 2000

	// fetch just the first page to get the real total
	// first, err := FetchAndWrite("0", "1", "./data/meta.json", apiKey)
	// if err != nil {
	// 	log.Fatal("Couldn't fetch metadata:", err)
	// }

	// total := first.TotalResults //
	// uncomment above code to find actual number

	total := 346996 // this number is from results page only
	log.Printf("Total CVEs: %d", total)

	return GetCorpus(total, pageSize, apiKey)
}

func GetEntireCorpusParallel(apiKey string) []parser.CVE {
	const pageSize = 2000

	total := 346996 // this number is from results page only
	log.Printf("Total CVEs: %d", total)

	return GetCorpusParallel(total, pageSize, apiKey)
}
