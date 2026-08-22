package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pinchtab/pinchtab/internal/scrape"
)

// fetch 是数据提取产品的快路径：输入一个 URL，用 seaportal 做 HTTP 提取，
// 输出正文 Markdown。静态站（服务端渲染）毫秒级完成，无需浏览器。
//
// 用法：
//
//	fetch <url> [outfile.md]
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fetch <url> [outfile.md]")
		os.Exit(1)
	}
	url := os.Args[1]

	// ValidateURL 留空，让 seaportal 的默认安全策略生效（阻止私网 IP，防 SSRF）。
	guard := scrape.CrawlGuard{MaxRedirects: 10}
	crawler := scrape.URLListCrawler([]string{url}, 30*time.Second, guard)

	report, err := scrape.Run(context.Background(),
		scrape.Input{URL: url},
		scrape.RunOptions{NoBrowser: true},
		crawler, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch error:", err)
		os.Exit(1)
	}
	if len(report.Pages) == 0 {
		fmt.Fprintln(os.Stderr, "no pages extracted")
		os.Exit(1)
	}

	p := report.Pages[0]
	if p.Error != "" {
		fmt.Fprintln(os.Stderr, "page error:", p.Error)
		os.Exit(1)
	}

	title := strings.TrimSpace(strings.TrimLeft(p.Title, "#"))
	out := fmt.Sprintf("# %s\n\n> 来源：%s\n\n%s\n", title, p.URL, p.Markdown)

	if len(os.Args) >= 3 {
		if err := os.WriteFile(os.Args[2], []byte(out), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write error:", err)
			os.Exit(1)
		}
		fmt.Printf("已保存：%s\n标题：%s\n正文：%d 字符\n", os.Args[2], p.Title, len(p.Markdown))
		return
	}
	fmt.Print(out)
}
