package parser

import "strings"

// NVDResponse -final api response
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// GetCVSSScore - Since CVSS can have two versions
func (c *CVE) GetCVSSScore() float64 {
	if len(c.Metrics.CVSSMetricV31) > 0 {
		return c.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(c.Metrics.CVSSMetricV2) > 0 {
		return c.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
	}
	return 0.0
}

func (c *CVE) ShouldIndex() bool {
	// are rejected CVE
	if strings.ToLower(c.VulnStatus) == "rejected" {
		return false
	}

	if len(c.Descriptions) > 0 {
		if strings.HasPrefix(c.Descriptions[0].Value, "Rejected Reason: ") {
			return false
		}
	}

	if c.GetCVSSScore() == 0.0 {
		return false
	}

	// if no Configurations : CPE then don't
	if len(c.Configurations) == 0 {
		return false
	}

	return true
}
