// Package lightpanda is a minimal CDP client for the Lightpanda browser
// engine. It drives the engine through the same session flow the engine
// requires — createBrowserContext → createTarget → attachToTarget — which
// plain Chrome-oriented clients skip.
//
// Lightpanda specifics handled here:
//   - the WebSocket endpoint must keep its trailing slash ("ws://host:port/");
//   - the handshake must NOT send an Origin header (gobwas/ws defaults to none);
//   - a single connection serves a single browsing context, so concurrency
//     comes from running several engine processes on several ports.
package lightpanda

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// Client is a live CDP session against one Lightpanda process.
type Client struct {
	conn    net.Conn
	nextID  int
	session string // set once attachToTarget returns a flattened session id
}

type cdpMsg struct {
	ID        int             `json:"id"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

type cdpResp struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *cdpErr         `json:"error,omitempty"`
}

type cdpErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Connect dials the Lightpanda CDP endpoint (host:port) and establishes a
// browsing-context session. The trailing slash is appended automatically.
func Connect(ctx context.Context, addr string) (*Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Trailing slash is required by Lightpanda; no Origin header is sent
	// (gobwas/ws does not add one), which Lightpanda also requires.
	conn, _, _, err := ws.Dial(dialCtx, "ws://"+addr+"/")
	if err != nil {
		return nil, fmt.Errorf("dial lightpanda %s: %w", addr, err)
	}

	c := &Client{conn: conn}
	if err := c.initSession(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) initSession(ctx context.Context) error {
	var br struct {
		BrowserContextID string `json:"browserContextId"`
	}
	if err := c.call(ctx, "Target.createBrowserContext", nil, &br); err != nil {
		return fmt.Errorf("createBrowserContext: %w", err)
	}

	createParams, _ := json.Marshal(map[string]any{
		"url":              "about:blank",
		"browserContextId": br.BrowserContextID,
	})
	var target struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call(ctx, "Target.createTarget", createParams, &target); err != nil {
		return fmt.Errorf("createTarget: %w", err)
	}

	attachParams, _ := json.Marshal(map[string]any{
		"targetId": target.TargetID,
		"flatten":  true,
	})
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.call(ctx, "Target.attachToTarget", attachParams, &attached); err != nil {
		return fmt.Errorf("attachToTarget: %w", err)
	}
	c.session = attached.SessionID
	return nil
}

// Render navigates to url, waits for the page to settle, and returns the
// rendered document HTML (outerHTML).
func (c *Client) Render(ctx context.Context, url string) (string, error) {
	for _, m := range []string{"Page.enable", "Network.enable"} {
		if err := c.call(ctx, m, nil, nil); err != nil {
			return "", err
		}
	}

	// Lightpanda's default UA is "Lightpanda/1.0", which many sites' WAFs
	// flag as a crawler. Override it with a normal browser UA before the
	// navigation so target sites serve their real content.
	uaParams, _ := json.Marshal(map[string]any{
		"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})
	if err := c.call(ctx, "Emulation.setUserAgentOverride", uaParams, nil); err != nil {
		return "", err
	}

	navParams, _ := json.Marshal(map[string]any{"url": url})
	if err := c.call(ctx, "Page.navigate", navParams, nil); err != nil {
		return "", err
	}

	// 等 DOM 稳定：轮询取 outerHTML 长度，连续两次一致才认为页面加载完成。
	// 固定等待窗口对慢站/动态站不够（会拿到半加载的页面），改成轮询直到稳定。
	evalParams, _ := json.Marshal(map[string]any{
		"expression":    "document.documentElement.outerHTML",
		"returnByValue": true,
	})
	var html string
	lastLen := -1
	stableCount := 0
	for i := 0; i < 15; i++ {
		time.Sleep(1 * time.Second)
		var eval struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		if err := c.call(ctx, "Runtime.evaluate", evalParams, &eval); err != nil {
			return "", err
		}
		html = eval.Result.Value
		l := len(html)
		if l == lastLen && l > 0 {
			stableCount++
			if stableCount >= 2 {
				break
			}
		} else {
			lastLen = l
			stableCount = 0
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}

	// 导航失败时 Lightpanda 会把错误渲染成页面内容，这里识别并报错，
	// 避免把「Navigation failed」错误页当成正文（否则会产生空↔残留的抖动误报）。
	if strings.Contains(html, "Navigation failed") {
		return "", fmt.Errorf("navigation failed (page did not load)")
	}
	return html, nil
}

// call sends one CDP command (session-scoped once attached) and blocks for
// the matching response, skipping over unrelated events.
func (c *Client) call(ctx context.Context, method string, params json.RawMessage, out any) error {
	c.nextID++
	id := c.nextID

	data, err := json.Marshal(cdpMsg{
		ID:        id,
		Method:    method,
		Params:    params,
		SessionID: c.session,
	})
	if err != nil {
		return err
	}
	if err := wsutil.WriteClientText(c.conn, data); err != nil {
		return err
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		payload, err := wsutil.ReadServerText(c.conn)
		if err != nil {
			return err
		}
		var r cdpResp
		if err := json.Unmarshal(payload, &r); err != nil {
			continue
		}
		if r.ID != id {
			continue
		}
		if r.Error != nil {
			return fmt.Errorf("cdp error %d: %s", r.Error.Code, r.Error.Message)
		}
		if out != nil && r.Result != nil {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}
}

// Close closes the underlying WebSocket connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
