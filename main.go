package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/rohit-Jung/search-engine/config"
	"github.com/rohit-Jung/search-engine/internal/fetcher"
	"github.com/rohit-Jung/search-engine/internal/parser"
)

func main() {
	_, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Error while reading env", err)
	}

	for i := 0; i < 2000; i += 100 {
		filePath := fmt.Sprintf("./data/data-%v.json", i)
		_, err := os.Stat(filePath)

		var result parser.NVDResponse

		if err != nil {
			fetchRes, err := nvd.FetchAndWrite(strconv.Itoa(i), "100", filePath)
			if err != nil {
				log.Fatal("Error while fetching", err)
			}

			result = *fetchRes
		} else {
			contents, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Println("Error reading data")
			}

			err = json.Unmarshal(contents, &result)
			if err != nil {
				log.Fatal("Failed to Unmarshal")
			}
		}

		// fmt.Println(result.ResultsPerPage, len(result.Vulnerabilities))
		for j := 0; j < result.ResultsPerPage; j++ {
			fmt.Println(j, result.Vulnerabilities[j].CVE.Descriptions[0].Value)
			// fmt.Println(j, result.Vulnerabilities[j].CVE.Published)
			// fmt.Println(j, result.Vulnerabilities[j].CVE.Configurations[0].Nodes[0].CPEMatch[0].GetCPEDetails().Version)
		}
	}
}
