// Command 2ms-web is a web-based, low-false-positive secret scanner built on top
// of the 2ms engine. It embeds the engine as a library and layers a precision
// pipeline (ingestion excludes, confidence scoring, learned false-positive
// allowlist) on top of the raw findings so that scanning arbitrary codebases
// surfaces real secrets while suppressing the noise that plagues generic rules.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/checkmarx/2ms/v5/lib/utils"
)

func main() {
	port := flag.Int("port", 8080, "preferred port; if busy, the next free port is used")
	host := flag.String("host", "127.0.0.1", "host/interface to bind to (use 0.0.0.0 to expose on your LAN)")
	dataDir := flag.String("data-dir", defaultDataDir(), "directory for persistent data (feedback allowlist)")
	logLevel := flag.String("log-level", "warn", "log level: trace, debug, info, warn, error")
	open := flag.Bool("open", true, "open the dashboard in your browser on startup")
	flag.Parse()

	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		level = zerolog.WarnLevel
	}
	zerolog.SetGlobalLevel(level)
	log.Logger = utils.CreateLogger(level)

	srv, err := NewServer(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}

	ln, err := listen(*host, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not bind to %s: %v\n", *host, err)
		os.Exit(1)
	}

	url := fmt.Sprintf("http://%s", ln.Addr().String())
	printBanner(url, *dataDir)
	if *open {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openBrowser(url)
		}()
	}

	if err := srv.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// listen binds to the preferred port, falling back to the next free one (and
// finally any OS-assigned port) so two people on the same machine, or a stale
// process, never block startup.
func listen(host string, port int) (net.Listener, error) {
	candidates := []string{
		fmt.Sprintf("%s:%d", host, port),
		fmt.Sprintf("%s:%d", host, port+1),
		fmt.Sprintf("%s:%d", host, port+2),
		fmt.Sprintf("%s:0", host), // any free port
	}
	var lastErr error
	for _, addr := range candidates {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func printBanner(url, dataDir string) {
	fmt.Println()
	fmt.Println("  2ms-web · low false-positive secret scanner")
	fmt.Println("  ------------------------------------------------")
	fmt.Printf("  Dashboard : %s\n", url)
	fmt.Printf("  Data dir  : %s\n", dataDir)
	fmt.Println("  Stop      : press Ctrl+C")
	fmt.Println()
}

// openBrowser best-effort opens url in the default browser; failures are ignored.
func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default: // linux, bsd, ...
		cmd = "xdg-open"
		args = []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".2ms-web"
	}
	return filepath.Join(home, ".2ms-web")
}
