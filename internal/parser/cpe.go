// Package parser - Here we have Cpe Parsing logic
package parser

import "strings"

type CPEDetails struct {
	Part    string
	Vendor  string
	Product string
	Version string
}

// GetCPEDetails - gives out splitted CPE
// CPE - Common Platform Enumeration
// Format - cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
func (c *CPEMatch) GetCPEDetails() *CPEDetails {
	parts := strings.Split(c.Criteria, ":")
	return &CPEDetails{
		Part:    parts[2],
		Vendor:  parts[3],
		Product: parts[4],
		Version: parts[5],
	}
}
