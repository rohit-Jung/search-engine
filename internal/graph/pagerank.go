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

	// iterate until convergence
	for range iterations {
		newScores := make(map[string]float64)
		maxDelta := 0.0

		// calculate new scores
		for id := range graph.Ajacency {
			newScores[id] = (1 - damping) / N

			// calc out degree
			for _, neighbor := range graph.Ajacency[id] {

				// this is the relations it have with other
				// sumation part we are calculating
				outDegrees := float64(len(graph.Ajacency[id]))
				if outDegrees > 0 {
					newScores[id] += damping * scores[neighbor] / outDegrees
				}

				delta := math.Abs(newScores[id] - scores[id])
				maxDelta = max(delta, maxDelta)
			}

		}

		scores = newScores
	}

	return internal.NormaliseMap(scores)
}
