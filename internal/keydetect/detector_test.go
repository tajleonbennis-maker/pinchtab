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
