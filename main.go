// Command cursedns is a skeleton recursive DNS server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"cursedns/resolver"
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
	handlerName := flag.String("handler", "static", `which Handler to use: "static" (fixed dummy answer) or "interactive" (prompts the operator at this terminal)`)
	staticIPv4 := flag.String("static-ipv4", "127.0.0.1", "IPv4 address returned by the dummy static handler for A queries (empty to disable)")
	staticIPv6 := flag.String("static-ipv6", "::1", "IPv6 address returned by the dummy static handler for AAAA queries (empty to disable)")
	staticTTL := flag.Uint("static-ttl", 60, "TTL, in seconds, applied to static handler answers")
	flag.Parse()

	if len(addrs) == 0 {
		addrs = listenAddrs{"127.0.0.1:5353"}
	}

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
	default:
		return fmt.Errorf("unknown -handler %q", *handlerName)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	server := &resolver.Server{
		Handler:        handler,
		RequestTimeout: *timeout,
		Logger:         logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("starting cursedns", "listen", []string(addrs), "timeout", timeout.String())
	if err := server.ListenAndServe(ctx, addrs); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
