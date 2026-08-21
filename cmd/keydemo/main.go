package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/pinchtab/pinchtab/internal/keydetect"
)

func main() {
	var data []byte
	var err error
	if len(os.Args) > 1 {
		data, err = os.ReadFile(os.Args[1])
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		os.Exit(1)
	}

	findings := keydetect.Detect(string(data))
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{
		"inputSize": len(data),
		"count":     len(findings),
		"findings":  findings,
	})
}
