package keydetect

import "testing"

func TestDetectOpenAIKey(t *testing.T) {
	content := `const key = "sk-abcdefghijklmnopqrstuvwxyz123456";`
	findings := Detect(content)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	found := false
	for _, f := range findings {
		if f.Kind == "rule" && f.Provider == "OpenAI" {
			found = true
			if f.MaskedKey != "sk-****3456" {
				t.Fatalf("unexpected mask: %q", f.MaskedKey)
			}
			if f.Fingerprint == "" {
				t.Fatal("expected non-empty fingerprint")
			}
		}
	}
	if !found {
		t.Fatalf("no OpenAI rule finding, got %+v", findings)
	}
}

func TestDetectAWSKey(t *testing.T) {
	findings := Detect("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
	for _, f := range findings {
		if f.Provider == "AWS" {
			return
		}
	}
	t.Fatal("expected AWS finding")
}

func TestDetectBearerToken(t *testing.T) {
	findings := Detect("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
	for _, f := range findings {
		if f.Kind == "rule" && f.MaskedKey == "abc****wxyz" {
			return
		}
	}
	t.Fatal("expected masked Bearer token finding")
}

func TestMask(t *testing.T) {
	if Mask("sk-abcdefghijklmnop") != "sk-****mnop" {
		t.Fatalf("unexpected mask %q", Mask("sk-abcdefghijklmnop"))
	}
	if Mask("short") != "*****" {
		t.Fatalf("unexpected short mask %q", Mask("short"))
	}
}

func TestEntropyAnchoredToSensitiveField(t *testing.T) {
	// A high-entropy value behind a sensitive field name is flagged.
	content := `{"api_key": "b4eb9b9063f24daf9e84075ec6aa5366"}`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "entropy" {
			return
		}
	}
	t.Fatalf("expected entropy finding for api_key value, got %+v", findings)
}

func TestEntropyIgnoresNonSensitiveContext(t *testing.T) {
	// High-entropy text that is not a sensitive assignment must not be flagged.
	content := `normalizeCodeBlockShowLineNumbers /_next/static/chunks/145f069teoa7h.js`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "entropy" {
			t.Fatalf("unexpected entropy finding: %+v", f)
		}
	}
}

func TestPlaceholderExcluded(t *testing.T) {
	findings := Detect(`{"api_key": "nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)
	for _, f := range findings {
		if f.MaskedKey == "nva****xxxx" {
			t.Fatalf("placeholder should be excluded, got %+v", f)
		}
	}
}

func TestProviderReclassified(t *testing.T) {
	content := `"base_url":"https://api.deepseek.com","api_key":"sk-b4eb9b9063f24daf9e84075ec6aa5366"`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "rule" {
			if f.Provider != "DeepSeek" {
				t.Fatalf("expected DeepSeek provider, got %q", f.Provider)
			}
			return
		}
	}
	t.Fatal("expected rule finding")
}
