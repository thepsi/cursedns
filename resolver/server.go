package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultRequestTimeout bounds how long a Handler has to produce a
	// Response before the server gives up and replies SERVFAIL.
	defaultRequestTimeout = 5 * time.Second

	// tcpIdleTimeout bounds how long a TCP connection may sit idle between
	// queries before the server closes it.
	tcpIdleTimeout = 30 * time.Second
)

// Server listens for DNS queries on one or more addresses and dispatches
// them to a Handler.
type Server struct {
	// Handler processes each inbound query. Required.
	Handler Handler

	// Cache backs Helper.Lookup. If nil, a fresh Cache is created.
	Cache *Cache

	// RootHints is returned by Helper.RootHints. If nil, the standard IANA
	// root hints are used.
	RootHints []NameServer

	// RequestTimeout bounds how long Handler.Handle may run before the
	// server replies SERVFAIL on its behalf. Defaults to 5s.
	RequestTimeout time.Duration

	// Logger receives per-request completion logs. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// TraceStore, if non-nil, records each request's trace detail (see
	// Helper.Trace) and appends a synthetic TXT record identifying it to
	// every response's Extra section, so it can be retrieved later (e.g.
	// via TraceStore.ServeHTTP). Nil disables the feature entirely: no TXT
	// record is added, and nothing is stored.
	TraceStore *TraceStore

	dnsClient *dns.Client

	mu        sync.Mutex
	listeners []io.Closer
	wg        sync.WaitGroup
}

// ListenAndServe opens a UDP and TCP listener for each address in addrs
// (each formatted as "host:port", host may be an IPv4 or IPv6 literal), and
// serves queries until ctx is cancelled. It blocks until shutdown is
// complete.
func (s *Server) ListenAndServe(ctx context.Context, addrs []string) error {
	if s.Handler == nil {
		return errors.New("resolver: Server.Handler must not be nil")
	}
	if s.Cache == nil {
		s.Cache = NewCache()
	}
	if s.RootHints == nil {
		s.RootHints = RootHints()
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = defaultRequestTimeout
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.dnsClient == nil {
		s.dnsClient = &dns.Client{Timeout: s.RequestTimeout}
	}
	if len(addrs) == 0 {
		return errors.New("resolver: at least one listen address is required")
	}

	for _, addr := range addrs {
		udpConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("listen udp %s: %w", addr, err)
		}
		s.listeners = append(s.listeners, udpConn)

		tcpLn, err := net.Listen("tcp", addr)
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("listen tcp %s: %w", addr, err)
		}
		s.listeners = append(s.listeners, tcpLn)

		s.Logger.Info("listening", "addr", addr)

		s.wg.Add(2)
		go func() {
			defer s.wg.Done()
			s.serveUDP(ctx, udpConn.(*net.UDPConn))
		}()
		go func() {
			defer s.wg.Done()
			s.serveTCP(ctx, tcpLn)
		}()
	}

	<-ctx.Done()
	s.closeListeners()
	s.wg.Wait()
	return ctx.Err()
}

func (s *Server) closeListeners() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
}

func (s *Server) serveUDP(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, dns.MaxMsgSize)
	for {
		n, clientAddr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Logger.Warn("udp read error", "error", err)
			continue
		}

		msg := append([]byte(nil), buf[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleMessage(ctx, msg, "udp", clientAddr, func(resp []byte) error {
				_, err := conn.WriteToUDPAddrPort(resp, clientAddr)
				return err
			})
		}()
	}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Logger.Warn("tcp accept error", "error", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.serveTCPConn(ctx, conn)
		}()
	}
}

func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn) {
	clientAddr, _ := netip.ParseAddrPort(conn.RemoteAddr().String())

	var lenBuf [2]byte
	for {
		conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf[:])

		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		s.handleMessage(ctx, msg, "tcp", clientAddr, func(resp []byte) error {
			var out [2]byte
			binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
			if _, err := conn.Write(out[:]); err != nil {
				return err
			}
			_, err := conn.Write(resp)
			return err
		})
	}
}

// handleMessage parses raw as a DNS query, dispatches it to s.Handler, and
// sends the resulting reply via respond.
func (s *Server) handleMessage(ctx context.Context, raw []byte, protocol string, clientAddr netip.AddrPort, respond func([]byte) error) {
	start := time.Now()

	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		s.Logger.Warn("dropping malformed dns message", "client", clientAddr, "protocol", protocol, "error", err)
		return
	}

	if len(req.Question) != 1 {
		s.sendReply(req, new(dns.Msg).SetRcode(req, dns.RcodeFormatError), protocol, respond)
		return
	}
	question := req.Question[0]

	if !req.RecursionDesired {
		reply := new(dns.Msg).SetRcode(req, dns.RcodeRefused)
		s.Logger.Info("request completed",
			"client", clientAddr,
			"protocol", protocol,
			"name", question.Name,
			"qtype", dns.TypeToString[question.Qtype],
			"rcode", dns.RcodeToString[reply.Rcode],
			"outcome", "refused: recursion not desired",
			"duration", time.Since(start),
		)
		s.sendReply(req, reply, protocol, respond)
		return
	}

	query := Query{
		ID:         req.Id,
		Name:       question.Name,
		Type:       question.Qtype,
		Class:      question.Qclass,
		ClientAddr: clientAddr,
		Protocol:   protocol,
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.RequestTimeout)
	defer cancel()

	helper := newRequestHelper(s.Cache, s.RootHints, s.dnsClient)

	type handlerResult struct {
		resp *Response
		err  error
	}
	resultCh := make(chan handlerResult, 1)
	go func() {
		resp, err := s.Handler.Handle(reqCtx, query, helper)
		resultCh <- handlerResult{resp, err}
	}()

	var reply *dns.Msg
	var outcome string
	select {
	case <-reqCtx.Done():
		reply = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		outcome = "timeout"
	case r := <-resultCh:
		switch {
		case r.err != nil:
			reply = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
			outcome = fmt.Sprintf("handler error: %v", r.err)
		case r.resp == nil:
			reply = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
			outcome = "handler returned nil response"
		default:
			reply = new(dns.Msg)
			reply.SetReply(req)
			reply.Rcode = r.resp.RCode
			reply.Answer = r.resp.Answer
			reply.Ns = r.resp.Ns
			reply.Extra = r.resp.Extra
			outcome = "ok"
		}
	}

	logArgs := []any{
		"client", clientAddr,
		"protocol", protocol,
		"name", question.Name,
		"qtype", dns.TypeToString[question.Qtype],
		"rcode", dns.RcodeToString[reply.Rcode],
		"outcome", outcome,
		"duration", time.Since(start),
		"trace", helper.traceLines(),
	}

	// A trace TXT record is appended last, deliberately: miekg/dns's
	// Truncate drops records from the point of overflow to the end of each
	// section, so appending last means this synthetic record is the first
	// thing sacrificed under a tight UDP size budget, protecting any real
	// glue/answer data the handler supplied.
	if s.TraceStore != nil {
		id, err := s.TraceStore.Put(TraceRecord{
			Name:       question.Name,
			QType:      dns.TypeToString[question.Qtype],
			RCode:      dns.RcodeToString[reply.Rcode],
			Outcome:    outcome,
			ClientAddr: clientAddr.String(),
			Protocol:   protocol,
			DurationMS: time.Since(start).Milliseconds(),
			Trace:      helper.traceLines(),
		})
		if err != nil {
			s.Logger.Warn("failed to record trace, omitting trace TXT", "error", err)
		} else {
			reply.Extra = append(reply.Extra, &dns.TXT{
				Hdr: dns.RR_Header{Name: "_cursedns-trace.invalid.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
				Txt: []string{id},
			})
			logArgs = append(logArgs, "trace_id", id)
		}
	}

	s.Logger.Info("request completed", logArgs...)

	s.sendReply(req, reply, protocol, respond)
}

// sendReply packs reply, truncating it for UDP if necessary, and sends it
// via respond.
//
// RecursionAvailable is set unconditionally here rather than by each
// caller: it describes this server's general capability (it always offers
// recursive service), not the outcome of any particular request, so it
// belongs on every reply - including error responses like SERVFAIL and
// REFUSED.
func (s *Server) sendReply(req, reply *dns.Msg, protocol string, respond func([]byte) error) {
	reply.RecursionAvailable = true

	if protocol == "udp" {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			if udpSize := int(opt.UDPSize()); udpSize > size {
				size = udpSize
			}
		}
		reply.Truncate(size)
	}

	out, err := reply.Pack()
	if err != nil {
		s.Logger.Error("failed to pack reply, falling back to servfail", "error", err)
		reply = new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		reply.RecursionAvailable = true
		out, err = reply.Pack()
		if err != nil {
			s.Logger.Error("failed to pack servfail fallback reply", "error", err)
			return
		}
	}

	if err := respond(out); err != nil {
		s.Logger.Warn("failed to send reply", "client", req.Id, "error", err)
	}
}
