package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pinchtab/pinchtab/internal/bridge"
	"github.com/pinchtab/pinchtab/internal/config"
	"github.com/pinchtab/pinchtab/internal/httpx"
	"github.com/pinchtab/pinchtab/internal/keydetect"
)

// Bounds for network-body retention during a single key search. Keeps memory
// bounded on small (1 GiB) worker nodes.
const (
	maxKeySearchBodies    = 24
	maxKeySearchBodyBytes = 256 << 10 // 256 KiB per body
	maxKeySearchTotal     = 8 << 20   // 8 MiB total
)

type keySearchRequest struct {
	URL string `json:"url"`
}

type keySearchResponse struct {
	URL      string              `json:"url"`
	Sources  []string            `json:"sources,omitempty"` // "html", "network"
	Findings []keydetect.Finding `json:"findings"`
	Count    int                 `json:"count"`
}

// @Endpoint POST /keysearch
// HandleKeySearch navigates to url, reads the rendered HTML and retained
// API/subresource response bodies, and scans the combined content for leaked
// keys. Keys are reported masked; full values are never returned.
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

	httpx.ExtendWriteDeadline(w, scrapeRunTimeout)
	runCtx, runCancel := context.WithTimeout(r.Context(), scrapeRunTimeout)
	defer runCancel()

	html, bodies, err := h.renderKeySearch(runCtx, req.URL, routing.EffectiveCfg, targets)
	if err != nil {
		httpx.Error(w, 400, fmt.Errorf("render: %w", err))
		return
	}

	content := html
	sources := []string{"html"}
	if len(bodies) > 0 {
		content += "\n" + strings.Join(bodies, "\n")
		sources = append(sources, "network")
	}

	findings := keydetect.Detect(content)
	httpx.JSON(w, 200, keySearchResponse{
		URL:      req.URL,
		Sources:  sources,
		Findings: findings,
		Count:    len(findings),
	})
}

// renderKeySearch navigates a fresh tab to url, reads the rendered HTML and the
// retained XHR/Fetch/Script response bodies, and returns them for key
// detection. The tab is always closed before returning.
func (h *Handlers) renderKeySearch(clientCtx context.Context, url string, cfg *config.RuntimeConfig, targets navTargets) (string, []string, error) {
	tabID, tabCtx, _, err := h.Bridge.CreateTab("")
	if err != nil {
		return "", nil, fmt.Errorf("new tab: %w", err)
	}
	defer func() { _ = h.Bridge.CloseTab(tabID) }()

	navTimeout := cfg.NavigateTimeout
	if navTimeout <= 0 {
		navTimeout = 30 * time.Second
	}
	navCtx, navCancel := context.WithTimeout(tabCtx, navTimeout)
	defer navCancel()

	navGuard, err := installNavigateRuntimeGuardWithBridge(h.Bridge, navCtx, navCancel, targets.target, targets.trustedCIDRs)
	if err != nil {
		return "", nil, fmt.Errorf("navigation guard: %w", err)
	}

	if _, navErr := h.Bridge.Navigate(navCtx, url, bridge.NavigateParams{MaxRedirects: cfg.MaxRedirects}); navErr != nil {
		if navGuard != nil {
			if blockedErr := navGuard.blocked(); blockedErr != nil {
				navErr = blockedErr
			}
		}
		return "", nil, navErr
	}

	if cur, urlErr := h.Bridge.CurrentURL(navCtx); urlErr == nil && strings.HasPrefix(cur, "chrome-error://") {
		return "", nil, h.documentNetError(tabID, url)
	}

	cCtx, cCancel := context.WithTimeout(tabCtx, scrapeRenderTimeout)
	defer cCancel()
	go httpx.CancelOnClientDone(clientCtx, cCancel)

	// Let JS rendering and late subresources (async fetches, dynamic chunks)
	// land before reading the DOM and the network capture.
	_, _ = bridge.WaitForQuietWindow(cCtx, 500*time.Millisecond, 5*time.Second)

	var html string
	if err := h.Bridge.Evaluate(cCtx, "document.documentElement.outerHTML", &html, bridge.EvalOpts{}); err != nil {
		return "", nil, fmt.Errorf("read rendered html: %w", err)
	}

	return html, h.collectResponseBodies(cCtx, tabID), nil
}

// collectResponseBodies reads the response bodies of the API and script
// requests recorded for tabID, within per-scan size limits. Body reads happen
// before the deferred CloseTab so the buffer is still populated.
func (h *Handlers) collectResponseBodies(ctx context.Context, tabID string) []string {
	nm := h.Bridge.NetworkMonitor()
	if nm == nil {
		return nil
	}
	buf := nm.GetBuffer(tabID)
	if buf == nil {
		return nil
	}

	var bodies []string
	var total int
	for _, e := range buf.List(bridge.NetworkFilter{}) {
		if len(bodies) >= maxKeySearchBodies {
			break
		}
		switch e.ResourceType {
		case "XHR", "Fetch", "Script":
		default:
			continue
		}
		body, _, err := bridge.GetResponseBody(ctx, e.RequestID)
		if err != nil || body == "" {
			continue
		}
		if len(body) > maxKeySearchBodyBytes {
			body = body[:maxKeySearchBodyBytes]
		}
		if total+len(body) > maxKeySearchTotal {
			break
		}
		bodies = append(bodies, body)
		total += len(body)
	}
	return bodies
}
