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

func (c *CVE) GetAttackVector() string {
	if len(c.Metrics.CVSSMetricV31) > 0 {
		av := strings.ToUpper(strings.TrimSpace(c.Metrics.CVSSMetricV31[0].CVSSData.AttackVector))
		if av != "" {
			return av
		}
	}
	if len(c.Metrics.CVSSMetricV2) > 0 {
		av := strings.ToUpper(strings.TrimSpace(c.Metrics.CVSSMetricV2[0].CVSSData.AccessVector))
		if av != "" {
			return av
		}
	}
	return ""
}

func (c *CVE) GetCWE() (id string, name string) {
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if v != "" {
				// NVD commonly provides values like "CWE-79".
				return v, ""
			}
		}
	}
	return "", ""
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
