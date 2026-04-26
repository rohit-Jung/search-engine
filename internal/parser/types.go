// Package parser - everything related to parsing
package parser

import (
	"strings"
	"time"
)

type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)

	// layout for parsing
	layout := "2006-01-02T15:04:05.000"
	parsed, err := time.Parse(layout, str)
	if err != nil {
		return err
	}

	ct.Time = parsed
	return nil
}

type LangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

type CPEMatch struct {
	Vulnerable      bool   `json:"vulnerable"`
	Criteria        string `json:"criteria"`
	MatchCriteriaID string `json:"matchCriteriaId"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type CVSSData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	AccessVector string  `json:"accessVector"`
}

type CVSSMetricV2 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CVSSData            CVSSData `json:"cvssData"`
	BaseSeverity        string   `json:"baseSeverity"`
	ExploitabilityScore float64  `json:"exploitabilityScore"`
	ImpactScore         float64  `json:"impactScore"`
}

type CVSSMetricV31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CVSSData            CVSSData `json:"cvssData"`
	BaseSeverity        string   `json:"baseSeverity"`
	ExploitabilityScore float64  `json:"exploitabilityScore"`
	ImpactScore         float64  `json:"impactScore"`
}

type Metrics struct {
	CVSSMetricV2  []CVSSMetricV2  `json:"cvssMetricV2"`
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31"`
}

type Weakness struct {
	Source      string      `json:"source"`
	Type        string      `json:"type"`
	Description []LangValue `json:"description"`
}

type CVE struct {
	ID               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        CustomTime      `json:"published"`
	LastModified     CustomTime      `json:"lastModified"`
	VulnStatus       string          `json:"vulnStatus"`
	Descriptions     []LangValue     `json:"descriptions"`
	Metrics          Metrics         `json:"metrics"`
	Weaknesses       []Weakness      `json:"weaknesses"`
	Configurations   []Configuration `json:"configurations"`
	References       []Reference     `json:"references"`
}

type Vulnerability struct {
	CVE CVE `json:"cve"`
}
