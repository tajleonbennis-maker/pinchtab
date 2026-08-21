package keydetect

import (
	"math"
	"regexp"
)

// minEntropyTokenLen is the shortest candidate value considered for entropy
// detection. Shorter values are too ambiguous to flag.
const minEntropyTokenLen = 16

// entropyThreshold is the bits-per-character above which a value is flagged.
// Because detection is anchored to a sensitive field name (see
// sensitiveFieldRe), the threshold can be lower than a full-text scan.
const entropyThreshold = 3.5

// sensitiveFieldRe anchors entropy detection to a sensitive field name
// followed by a quoted value (group 1 = field name, group 2 = value). This is
// what keeps the signal-to-noise ratio usable: variable names, file paths and
// base64 RSC flight payloads are high-entropy too, but they never appear as the
// value of an api_key/token/secret assignment, so they are excluded by design.
var sensitiveFieldRe = regexp.MustCompile(`(?i)["']?(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|app[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|private[_-]?key|password|credential|bearer)["']?\s*[:=]\s*["']([^"'\\]{16,})["']`)

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// isFalsePositive rejects values that are identifiers or paths rather than
// secrets. Real secrets almost always mix letters and digits; a purely
// alphabetic camelCase identifier is not one.
func isFalsePositive(s string) bool {
	hasDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if c == '/' || c == ' ' || c == '\\' {
			return true
		}
	}
	return !hasDigit
}

// detectEntropy flags high-entropy values found in sensitive assignments. It is
// the fallback for providers we do not have a shape rule for.
func detectEntropy(content string) []Finding {
	var out []Finding
	for _, m := range sensitiveFieldRe.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 6 || m[4] < 0 {
			continue
		}
		start, end := m[4], m[5]
		val := content[start:end]
		if len(val) < minEntropyTokenLen {
			continue
		}
		if isFalsePositive(val) {
			continue
		}
		if shannonEntropy(val) < entropyThreshold {
			continue
		}
		out = append(out, Finding{
			Provider:    classify(val, content, start),
			Kind:        "entropy",
			MaskedKey:   Mask(val),
			Fingerprint: Fingerprint(val),
			Confidence:  "low",
			Offset:      start,
			Context:     contextAround(content, start, end),
		})
	}
	return out
}
