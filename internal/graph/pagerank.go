// Package graph
package graph

import (
	"math"

	"github.com/rohit-Jung/search-engine/internal"
)

const (
	damping    = 0.85 // Beta
	iterations = 50
	threshold  = 0.0001 // convergence threshold
)

// formula = (1 - B) / N  + B * SUM
// (1 - damping) / N
//   - damping × Σ (rank[neighbour] / out_degree[neighbour]):
func RunPageRank(graph *Graph) map[string]float64 {
	N := float64(len(graph.Ajacency)) // total nodes

	if N == 0.0 {
		return map[string]float64{}
	}

	// initialise all scores equally 1/ N
	scores := make(map[string]float64)
	for id := range graph.Ajacency {
		scores[id] = 1.0 / N
	}

	// iterate until convergence (or iteration cap)
	for range iterations {
		newScores := make(map[string]float64)
		maxDelta := 0.0

		// calculate new scores
		for id := range graph.Ajacency {
			newScores[id] = (1 - damping) / N
			for _, neighbor := range graph.Ajacency[id] {
				outDegree := float64(len(graph.Ajacency[neighbor]))
				if outDegree == 0 {
					continue
				}
				newScores[id] += damping * scores[neighbor] / outDegree
			}
		}

		for id := range graph.Ajacency {
			delta := math.Abs(newScores[id] - scores[id])
			maxDelta = max(delta, maxDelta)
		}

		scores = newScores
		if maxDelta < threshold {
			break
		}
	}

	return internal.NormaliseMap(scores)
}
