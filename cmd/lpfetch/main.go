package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	seaportal "github.com/pinchtab/seaportal"

	"github.com/pinchtab/pinchtab/internal/lightpanda"
)

// lpfetch 是数据提取的慢路径：用 Lightpanda 真实加载页面（执行 JS、发起请求），
// 再复用 seaportal 把渲染后的 HTML 提取成正文 Markdown。适合动态站 / 需要
// 浏览器渲染的页面，与 cmd/fetch 的快路径（纯 HTTP 提取）互补。
//
// 用法：
//
//	lpfetch -lp 127.0.0.1:9222 <url> [outfile.md]
func main() {
	lpAddr := flag.String("lp", "127.0.0.1:9222", "Lightpanda CDP address (host:port)")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: lpfetch -lp 127.0.0.1:9222 <url> [outfile.md]")
		os.Exit(1)
	}
	url := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client, err := lightpanda.Connect(ctx, *lpAddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect error:", err)
		os.Exit(1)
	}
	defer client.Close()

	html, err := client.Render(ctx, url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "render error:", err)
		os.Exit(1)
	}

	r := seaportal.FromHTML(html, url)
	if r.Error != "" {
		fmt.Fprintln(os.Stderr, "extract error:", r.Error)
		os.Exit(1)
	}

	title := strings.TrimSpace(strings.TrimLeft(r.Title, "#"))
	out := fmt.Sprintf("# %s\n\n> 来源：%s（Lightpanda 渲染）\n\n%s\n", title, url, r.Content)

	if len(args) >= 2 {
		if err := os.WriteFile(args[1], []byte(out), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write error:", err)
			os.Exit(1)
		}
		fmt.Printf("已保存：%s\n标题：%s\n正文：%d 字符\n", args[1], title, len(r.Content))
		return
	}
	fmt.Print(out)
}
