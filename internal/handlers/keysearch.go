package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pinchtab/pinchtab/internal/httpx"
	"github.com/pinchtab/pinchtab/internal/keydetect"
)

type keySearchRequest struct {
	URL string `json:"url"`
}

type keySearchResponse struct {
	URL      string              `json:"url"`
	Findings []keydetect.Finding `json:"findings"`
	Count    int                 `json:"count"`
}

// @Endpoint POST /keysearch
// HandleKeySearch navigates to url, reads the rendered HTML, and scans it for
// leaked API keys. Keys are reported masked; full values are never returned.
func (h *Handlers) HandleKeySearch(w http.ResponseWriter, r *http.Request) {
	var req keySearchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize)).Decode(&req); err != nil {
		httpx.Error(w, 400, fmt.Errorf("decode: %w", err))
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		httpx.Error(w, 400, fmt.Errorf("url required"))
		return
	}

	routing, ok := h.resolveNavigateBrowser(w, r, "", "")
	if !ok {
		return
	}
	targets, err := h.validateAuditTarget(req.URL, routing.EffectiveCfg)
	if err != nil {
		httpx.Error(w, 400, err)
		return
	}
	if !h.ensureBrowserOrRespond(w, routing.EffectiveCfg) {
		return
	}

	// A key search renders one page; bound it the same way a scrape render is
	// bounded so the write deadline outlives the server default.
	httpx.ExtendWriteDeadline(w, scrapeRunTimeout)
	runCtx, runCancel := context.WithTimeout(r.Context(), scrapeRunTimeout)
	defer runCancel()

	html, err := h.renderPageHTML(runCtx, req.URL, routing.EffectiveCfg, targets)
	if err != nil {
		httpx.Error(w, 400, fmt.Errorf("render: %w", err))
		return
	}

	findings := keydetect.Detect(html)
	httpx.JSON(w, 200, keySearchResponse{
		URL:      req.URL,
		Findings: findings,
		Count:    len(findings),
	})
}
