package main

import (
	"log"
	"os"

	fetcher "github.com/rohit-Jung/search-engine/internal/fetcher"
)

func main() {
	apiKey := os.Getenv("NVD_API_KEY")
	if apiKey == "" {
		log.Println("Warning: NVD_API_KEY not set. Rate limited to 5 requests/30s")
	}

	log.Println("Fetching entire NVD corpus (~347k CVEs)...")
	cves := fetcher.GetEntireCorpusParallel(apiKey)
	log.Printf("Fetched %d CVEs", len(cves))
}
