package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	seaportal "github.com/pinchtab/seaportal"
)

// allowPrivate 打开后允许监控内网/私网地址（如 127.0.0.1、192.168.x.x）。
// 默认关闭以保留 SSRF 防护；监控企业内网站点时可设 MONITOR_ALLOW_PRIVATE=1。
var allowPrivate = os.Getenv("MONITOR_ALLOW_PRIVATE") == "1"

//go:embed index.html
var indexHTML string

// Target 是一个被监控的网页。
type Target struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Interval    string    `json:"interval"`
	LastHash    string    `json:"lastHash,omitempty"`
	LastCheck   time.Time `json:"lastCheck,omitempty"`
	Status      string    `json:"status"` // ok / changed / error
	LastError   string    `json:"lastError,omitempty"`
	ChangeCount int       `json:"changeCount"`
}

// Snapshot 是一次抓取的内容快照（正文截断存储）。
type Snapshot struct {
	Time   time.Time `json:"time"`
	Hash   string    `json:"hash"`
	Length int       `json:"length"`
	Head   string    `json:"head"`
}

// ChangeEvent 记录一次内容变化。
type ChangeEvent struct {
	Time     time.Time `json:"time"`
	FromHash string    `json:"fromHash"`
	ToHash   string    `json:"toHash"`
	OldLen   int       `json:"oldLen"`
	NewLen   int       `json:"newLen"`
	Diff     string    `json:"diff"`
}

type Monitor struct {
	mu      sync.Mutex
	targets map[string]*Target
	history map[string][]Snapshot
	events  map[string][]ChangeEvent
	stops   map[string]chan struct{}
	seq     int
}

func NewMonitor() *Monitor {
	return &Monitor{
		targets: map[string]*Target{},
		history: map[string][]Snapshot{},
		events:  map[string][]ChangeEvent{},
		stops:   map[string]chan struct{}{},
	}
}

// add 注册一个监控目标并启动后台抓取循环。
func (m *Monitor) add(url, interval string) (*Target, error) {
	d, err := time.ParseDuration(interval)
	if err != nil {
		return nil, fmt.Errorf("invalid interval: %w", err)
	}
	if d < 10*time.Second {
		return nil, fmt.Errorf("interval too short (min 10s)")
	}

	m.mu.Lock()
	m.seq++
	t := &Target{
		ID:       fmt.Sprintf("t%03d", m.seq),
		URL:      url,
		Interval: interval,
		Status:   "ok",
	}
	m.targets[t.ID] = t
	stop := make(chan struct{})
	m.stops[t.ID] = stop
	m.mu.Unlock()

	go m.loop(t, d, stop)
	// 立即抓一次，让用户马上看到结果。
	go m.check(t)
	return t, nil
}

func (m *Monitor) loop(t *Target, d time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.check(t)
		case <-stop:
			return
		}
	}
}

// check 抓取一次并做 hash 对比。
func (m *Monitor) check(t *Target) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	policy := seaportal.DefaultSecurityPolicy()
	if allowPrivate {
		policy.BlockPrivateIPs = false
	}
	body, _, _, err := seaportal.FetchBytes(ctx, t.URL, seaportal.FetchBytesOptions{
		Security: policy,
		Timeout:  30 * time.Second,
	})

	m.mu.Lock()
	defer m.mu.Unlock()

	if err != nil {
		t.Status = "error"
		t.LastError = err.Error()
		t.LastCheck = time.Now()
		return
	}

	hash := sha256Hex(body)
	r := seaportal.FromHTML(string(body), t.URL)
	content := r.Content

	oldHash := t.LastHash
	oldSnap := latestSnapshot(m.history[t.ID])

	if oldHash != "" && oldHash != hash {
		// 内容变了
		t.Status = "changed"
		t.ChangeCount++
		ev := ChangeEvent{
			Time:     time.Now(),
			FromHash: oldHash,
			ToHash:   hash,
			OldLen:   oldSnap.Length,
			NewLen:   len(content),
			Diff:     diffSummary(oldSnap.Head, content),
		}
		m.events[t.ID] = append(m.events[t.ID], ev)
	} else {
		t.Status = "ok"
		t.LastError = ""
	}

	t.LastHash = hash
	t.LastCheck = time.Now()

	snap := Snapshot{
		Time:   time.Now(),
		Hash:   hash,
		Length: len(content),
		Head:   truncate(content, 600),
	}
	m.history[t.ID] = append(m.history[t.ID], snap)
	if len(m.history[t.ID]) > 20 {
		m.history[t.ID] = m.history[t.ID][len(m.history[t.ID])-20:]
	}
}

func (m *Monitor) remove(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[id]; !ok {
		return false
	}
	if stop, ok := m.stops[id]; ok {
		close(stop)
	}
	delete(m.targets, id)
	delete(m.history, id)
	delete(m.events, id)
	delete(m.stops, id)
	return true
}

// ---- helpers ----

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func latestSnapshot(ss []Snapshot) Snapshot {
	if len(ss) == 0 {
		return Snapshot{}
	}
	return ss[len(ss)-1]
}

// diffSummary 生成一个行级差异摘要，展示变化点前后的内容。
func diffSummary(old, new string) string {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")
	i := 0
	for i < len(oldLines) && i < len(newLines) && oldLines[i] == newLines[i] {
		i++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "第 %d 行起有差异", i+1)
	if i < len(oldLines) {
		b.WriteString("；旧：")
		for j := i; j < len(oldLines) && j < i+2; j++ {
			b.WriteString(" " + strings.TrimSpace(oldLines[j]))
		}
	}
	if i < len(newLines) {
		b.WriteString("；新：")
		for j := i; j < len(newLines) && j < i+2; j++ {
			b.WriteString(" " + strings.TrimSpace(newLines[j]))
		}
	}
	return b.String()
}

// ---- HTTP handlers ----

func (m *Monitor) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (m *Monitor) handleList(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := make([]Target, 0, len(m.targets))
	for _, t := range m.targets {
		list = append(list, *t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	writeJSON(w, 200, list)
}

func (m *Monitor) handleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		Interval string `json:"interval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad request"})
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" || !strings.HasPrefix(req.URL, "http") {
		writeJSON(w, 400, map[string]string{"error": "url must start with http/https"})
		return
	}
	t, err := m.add(req.URL, req.Interval)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, t)
}

func (m *Monitor) handleRemove(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	if !m.remove(id) {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (m *Monitor) handleChanges(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	id = strings.TrimSuffix(id, "/changes")
	m.mu.Lock()
	defer m.mu.Unlock()
	evs := m.events[id]
	if evs == nil {
		evs = []ChangeEvent{}
	}
	writeJSON(w, 200, evs)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	m := NewMonitor()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", m.handleIndex)
	mux.HandleFunc("GET /api/targets", m.handleList)
	mux.HandleFunc("POST /api/targets", m.handleAdd)
	mux.HandleFunc("DELETE /api/targets/", m.handleRemove)
	mux.HandleFunc("GET /api/targets/", m.handleChanges)

	addr := ":8080"
	fmt.Println("WebLens 监控巡检已启动：http://localhost" + addr)
	_ = http.ListenAndServe(addr, mux)
}
