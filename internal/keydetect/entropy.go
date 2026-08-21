package keydetect

import (
	"math"
	"regexp"
)

// minEntropyTokenLen is the shortest candidate token considered for entropy
// detection. Shorter tokens are too ambiguous to flag.
const minEntropyTokenLen = 20

// entropyThreshold is the bits-per-character above which a token is flagged.
// API keys are high-entropy; human-readable identifiers are not.
const entropyThreshold = 4.2

var entropyTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)

// shannonEntropy returns entropy in bits per character.
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

// detectEntropy flags high-entropy tokens that match no known shape. This is
// the fallback for providers we do not have a rule for.
func detectEntropy(content string) []Finding {
	var out []Finding
	for _, m := range entropyTokenRe.FindAllStringIndex(content, -1) {
		tok := content[m[0]:m[1]]
		if len(tok) < minEntropyTokenLen {
			continue
		}
		if shannonEntropy(tok) < entropyThreshold {
			continue
		}
		out = append(out, Finding{
			Provider:    classify(tok, content, m[0]),
			Kind:        "entropy",
			MaskedKey:   Mask(tok),
			Fingerprint: Fingerprint(tok),
			Confidence:  "low",
			Offset:      m[0],
			Context:     contextAround(content, m[0], m[1]),
		})
	}
	return out
}
