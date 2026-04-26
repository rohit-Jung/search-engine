// Package nvd - about fetching the nvd and unmarshaling
package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/rohit-Jung/search-engine/internal/parser"
)

func FetchAndWrite(
	startIndex string,
	resultsPerPage string,
	filePath string,
) (*parser.NVDResponse, error) {
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdURL, _ := url.Parse(baseURL)
	q := nvdURL.Query()
	q.Set("startIndex", startIndex)
	q.Set("resultsPerPage", resultsPerPage)
	// q.Set("apiKey", apiKey)

	nvdURL.RawQuery = q.Encode()
	fmt.Printf("fetching, %s", nvdURL.String())

	res, err := http.Get(nvdURL.String())
	if err != nil {
		log.Fatal("Error while fetching data")
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal("Error while fetching data")
		return nil, err
	}

	err = os.WriteFile(filePath, []byte(string(body)), 0644)
	if err != nil {
		log.Fatal("Couldn't write to a file")
		return nil, err
	}

	var nvdRes parser.NVDResponse
	json.Unmarshal(body, &nvdRes)
	return &nvdRes, nil
}
