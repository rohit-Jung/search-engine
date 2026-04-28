// Package internal
package internal

import "math"

func NormaliseMap(scores map[string]float64) map[string]float64 {
	// find min and max in map
	min, max := math.MaxFloat64, -math.MaxFloat64
	for _, v := range scores {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	// find diff and normalise(-min / diff)
	diff := max - min
	result := make(map[string]float64)
	for id, v := range scores {
		if diff == 0 {
			result[id] = 0
		} else {
			result[id] = (v - min) / diff
		}
	}

	return result
}
