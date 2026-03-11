package scan

import (
	"math"
	"strings"
)

const entropyThreshold = 4.5

// shannonEntropy computes the Shannon entropy of s in bits.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isHighEntropyToken returns true when s has entropy ≥ threshold and length ≥ 20.
func isHighEntropyToken(s string) bool {
	if len(s) < 20 {
		return false
	}
	return shannonEntropy(s) >= entropyThreshold
}

// sensitiveKeywords trigger entropy scanning when found on the same line.
var sensitiveKeywords = []string{
	"key", "secret", "token", "password", "passwd", "pass", "pwd",
	"auth", "credential", "cred", "private", "signing",
	"access", "api", "bearer", "session",
}

// lineHasSecretContext returns true when the line contains a credential-related keyword.
func lineHasSecretContext(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// extractHighEntropyTokens returns tokens from line that pass the entropy threshold.
func extractHighEntropyTokens(line string) []string {
	var matches []string
	for _, token := range splitTokens(line) {
		if isHighEntropyToken(token) {
			matches = append(matches, token)
		}
	}
	return matches
}

// splitTokens splits a line on common separators and returns candidate tokens of ≥20 chars.
func splitTokens(line string) []string {
	for _, sep := range []string{"=", ":", `"`, "'", "`", ",", ";"} {
		line = strings.ReplaceAll(line, sep, " ")
	}
	var tokens []string
	for _, t := range strings.Fields(line) {
		if len(t) >= 20 {
			tokens = append(tokens, t)
		}
	}
	return tokens
}
