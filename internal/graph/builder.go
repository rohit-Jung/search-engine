// Package graph
package graph

import "github.com/rohit-Jung/search-engine/internal/parser"

type Graph struct {
	Ajacency map[string][]string
}

func BuildGraph(allCves []parser.CVE) *Graph {
	productMap := make(map[string][]string)

	for _, cve := range allCves {
		for _, conf := range cve.Configurations {
			for _, node := range conf.Nodes {
				for _, cpe := range node.CPEMatch {
					cpeDetails := cpe.GetCPEDetails()
					productMap[cpeDetails.Product] = append(productMap[cpeDetails.Product], cve.ID)
				}
			}
		}
	}

	// build the graph
	adjacency := make(map[string][]string)
	for product := range productMap {
		cves := productMap[product]
		// cap at 50 to avoid explosion on common products
		// e.g. "linux_kernel" has thousands of CVEs
		if len(cves) > 50 {
			cves = cves[:50]
		}

		// get adjcent and connect them { classic adj map representation }
		for i := range cves {
			for j := i + 1; j < len(cves); j++ {
				a, b := cves[i], cves[j]
				// bidirectional graph ?
				adjacency[a] = append(adjacency[a], b)
				adjacency[b] = append(adjacency[b], a)
			}
		}
	}

	return &Graph{
		Ajacency: adjacency,
	}
}
