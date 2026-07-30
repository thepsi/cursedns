// Command cursedns is a skeleton recursive DNS server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"cursedns/resolver"
	"google.golang.org/genai"
)

// listenAddrs collects repeated -listen flag values.
type listenAddrs []string

func (l *listenAddrs) String() string     { return strings.Join(*l, ",") }
func (l *listenAddrs) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var addrs listenAddrs
	flag.Var(&addrs, "listen", "address:port to listen on (IPv4 or IPv6, may be given multiple times)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-request timeout before responding SERVFAIL")
	handlerName := flag.String("handler", "static", `which Handler to use: "static" (fixed dummy answer), "interactive" (prompts the operator at this terminal), "recursive" (real iterative resolution starting from the root), or "gemini" (delegates resolution decisions to the Gemini API)`)
	staticIPv4 := flag.String("static-ipv4", "127.0.0.1", "IPv4 address returned by the dummy static handler for A queries (empty to disable)")
	staticIPv6 := flag.String("static-ipv6", "::1", "IPv6 address returned by the dummy static handler for AAAA queries (empty to disable)")
	staticTTL := flag.Uint("static-ttl", 60, "TTL, in seconds, applied to static handler answers")
	geminiModel := flag.String("gemini-model", "gemini-2.5-flash", "Gemini model to use for the gemini handler")
	geminiMaxTurns := flag.Int("gemini-max-turns", 0, "max model round-trips per request for the gemini handler (0 = handler default)")
	geminiMaxTokens := flag.Int("gemini-max-tokens", 0, "max cumulative token budget per request for the gemini handler (0 = handler default)")
	traceHTTPListen := flag.String("trace-http-listen", "", "if set, address:port to serve per-request trace lookups on (GET /trace/{id}); empty disables the feature entirely")
	traceCapacity := flag.Int("trace-capacity", 1000, "number of recent traces to keep in memory (LRU-evicted) when -trace-http-listen is set")
	flag.Parse()

	if len(addrs) == 0 {
		addrs = listenAddrs{"127.0.0.1:5353"}
	}
	if *traceHTTPListen != "" && *traceCapacity <= 0 {
		return fmt.Errorf("invalid -trace-capacity %d: must be positive when -trace-http-listen is set", *traceCapacity)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var handler resolver.Handler
	switch *handlerName {
	case "static":
		staticHandler := &resolver.StaticHandler{TTL: uint32(*staticTTL)}
		if *staticIPv4 != "" {
			addr, err := netip.ParseAddr(*staticIPv4)
			if err != nil {
				return fmt.Errorf("invalid -static-ipv4: %w", err)
			}
			staticHandler.IPv4 = addr
		}
		if *staticIPv6 != "" {
			addr, err := netip.ParseAddr(*staticIPv6)
			if err != nil {
				return fmt.Errorf("invalid -static-ipv6: %w", err)
			}
			staticHandler.IPv6 = addr
		}
		handler = staticHandler
	case "interactive":
		handler = resolver.NewInteractiveHandler(os.Stdin, os.Stdout)
		timeoutSet := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "timeout" {
				timeoutSet = true
			}
		})
		if !timeoutSet {
			// A human at a terminal needs far longer than the 5s default
			// meant for an automated handler.
			*timeout = 5 * time.Minute
		}
	case "recursive":
		handler = &resolver.RecursiveHandler{}
	case "gemini":
		// genai.NewClient reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the
		// environment when ClientConfig is nil.
		client, err := genai.NewClient(ctx, nil)
		if err != nil {
			return fmt.Errorf("creating gemini client (is GEMINI_API_KEY set?): %w", err)
		}
		handler = &resolver.GeminiHandler{
			Client:         client.Models,
			Model:          *geminiModel,
			MaxTurns:       *geminiMaxTurns,
			MaxTokenBudget: int32(*geminiMaxTokens),
		}
	default:
		return fmt.Errorf("unknown -handler %q", *handlerName)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	server := &resolver.Server{
		Handler:        handler,
		RequestTimeout: *timeout,
		Logger:         logger,
	}

	var httpWG sync.WaitGroup
	if *traceHTTPListen != "" {
		traceStore := resolver.NewTraceStore(*traceCapacity)
		server.TraceStore = traceStore

		ln, err := net.Listen("tcp", *traceHTTPListen)
		if err != nil {
			return fmt.Errorf("listen http %s: %w", *traceHTTPListen, err)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /trace/{id}", traceStore)
		httpServer := &http.Server{Handler: mux}

		logger.Info("listening (trace http)", "addr", *traceHTTPListen)
		httpWG.Add(1)
		go func() {
			defer httpWG.Done()
			if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
				logger.Warn("trace http server error", "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			httpServer.Close()
		}()
	}

	logger.Info("starting cursedns", "listen", []string(addrs), "timeout", timeout.String())
	err := server.ListenAndServe(ctx, addrs)
	httpWG.Wait()
	if err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
