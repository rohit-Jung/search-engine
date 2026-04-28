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
	"time"

	"github.com/rohit-Jung/search-engine/internal/parser"
)

func FetchAndWrite(
	startIndex string,
	resultsPerPage string,
	filePath string,
	apiKey string,
) (*parser.NVDResponse, error) {
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdURL, _ := url.Parse(baseURL)
	q := nvdURL.Query()
	q.Set("startIndex", startIndex)
	q.Set("resultsPerPage", resultsPerPage)
	nvdURL.RawQuery = q.Encode()

	// use http.newrequest so you can set headers
	req, err := http.NewRequest("GET", nvdURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	if apiKey != "" {
		req.Header.Set("apiKey", apiKey) // pass in the header
	}

	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)

	log.Printf("fetching %s\n", nvdURL.String())
	if err != nil {
		return nil, fmt.Errorf("fetching data: %w", err)
	}
	defer res.Body.Close()

	// check http status before reading body
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("NVD returned %d: %s", res.StatusCode, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON response: %s", string(body))
	}

	if err = os.WriteFile(filePath, body, 0o644); err != nil {
		return nil, fmt.Errorf("writing file: %w", err)
	}

	var nvdRes parser.NVDResponse
	if err = json.Unmarshal(body, &nvdRes); err != nil {
		return nil, fmt.Errorf("unmarshalling response: %w", err)
	}

	return &nvdRes, nil
}
