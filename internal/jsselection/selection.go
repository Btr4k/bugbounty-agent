// Package jsselection defines the shared deterministic budget policy for
// JavaScript download and AI analysis.
package jsselection

import "strings"

const MaxFiles = 25

// PriorityScore favors likely first-party application bundles and deprioritizes
// generated vendor/runtime chunks. It is only a bounded-work ordering heuristic;
// it does not classify a file as safe or uninteresting.
func PriorityScore(raw string) int {
	lower := strings.ToLower(raw)
	score := 0
	if strings.Contains(lower, "vendor") || strings.Contains(lower, "polyfill") ||
		strings.Contains(lower, "chunk") || strings.Contains(lower, "runtime") {
		score -= 10
	}
	if strings.Contains(lower, "app") || strings.Contains(lower, "main") ||
		strings.Contains(lower, "index") || strings.Contains(lower, "bundle") ||
		strings.Contains(lower, "config") || strings.Contains(lower, "api") {
		score += 10
	}
	return score
}

// Less orders higher-priority URLs first and applies a lexical tie-break.
func Less(left, right string) bool {
	leftScore, rightScore := PriorityScore(left), PriorityScore(right)
	if leftScore != rightScore {
		return leftScore > rightScore
	}
	leftLower, rightLower := strings.ToLower(left), strings.ToLower(right)
	if leftLower != rightLower {
		return leftLower < rightLower
	}
	return left < right
}
