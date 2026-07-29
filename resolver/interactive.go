package resolver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// InteractiveHandler is a Handler that lets a human operator resolve each
// query by hand: it prints the query to w, then reads commands from r that
// invoke Helper methods or compose the final Response.
//
// Since there is only one operator, InteractiveHandler handles one query at
// a time. While a query is being worked on, any other query that reaches
// it fails immediately (the server responds SERVFAIL) rather than
// queueing, so a slow or absent operator can't back up the server. The
// busy period ends only when the operator actually finishes the current
// query (via "respond" or "fail") — it is not tied to the request context
// deadline, since the terminal is a real, single-slot resource: if the
// operator doesn't respond, nothing else can use it regardless of what the
// original client's request timeout does in the meantime.
type InteractiveHandler struct {
	r    *bufio.Reader
	w    io.Writer
	busy chan struct{}
}

// NewInteractiveHandler returns an InteractiveHandler reading commands from
// r and writing prompts/output to w.
func NewInteractiveHandler(r io.Reader, w io.Writer) *InteractiveHandler {
	return &InteractiveHandler{
		r:    bufio.NewReader(r),
		w:    w,
		busy: make(chan struct{}, 1),
	}
}

func (h *InteractiveHandler) Handle(ctx context.Context, query Query, helper Helper) (*Response, error) {
	select {
	case h.busy <- struct{}{}:
	default:
		return nil, errors.New("interactive handler: an operator is already handling another query")
	}
	defer func() { <-h.busy }()

	fmt.Fprintf(h.w, "\n=== query from %s (%s) ===\n", query.ClientAddr, query.Protocol)
	sess := &interactiveSession{
		ctx:    ctx,
		query:  query,
		helper: helper,
		w:      h.w,
		roots:  helper.RootHints(),
	}
	sess.printQuery()
	fmt.Fprintln(h.w, `type "help" for commands`)

	for {
		fmt.Fprint(h.w, "> ")
		line, err := h.r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("interactive handler: reading command: %w", err)
		}

		result, cmdErr := sess.dispatch(strings.TrimSpace(line))
		if cmdErr != nil {
			fmt.Fprintf(h.w, "error: %v\n", cmdErr)
			continue
		}
		if result == nil {
			continue
		}
		if ctx.Err() != nil {
			fmt.Fprintf(h.w, "note: this query already timed out server-side (%v); the client was already sent SERVFAIL.\n", ctx.Err())
		}
		return result.response, result.err
	}
}

// interactiveSession holds the state of one in-progress interactive query:
// the sections being built up for the eventual response.
type interactiveSession struct {
	ctx    context.Context
	query  Query
	helper Helper
	w      io.Writer
	roots  []NameServer

	pendingAnswer []dns.RR
	pendingNs     []dns.RR
	pendingExtra  []dns.RR
}

// replResult is non-nil once the operator has decided how to conclude the
// query, either successfully (response set) or with a failure (err set).
type replResult struct {
	response *Response
	err      error
}

// dispatch executes one command line. A non-nil cmdErr means the command
// was rejected (bad syntax, unknown command, ...) and should be shown to
// the operator so they can try again; it never ends the session.
func (s *interactiveSession) dispatch(line string) (result *replResult, cmdErr error) {
	if line == "" {
		return nil, nil
	}
	fields := strings.Fields(line)
	cmd := strings.ToLower(fields[0])
	args := fields[1:]

	switch cmd {
	case "help":
		s.printHelp()
	case "query":
		s.printQuery()
	case "roothints":
		s.printRootHints()
	case "trace":
		if len(args) == 0 {
			return nil, errors.New(`usage: trace <message>`)
		}
		s.helper.Trace("%s", strings.Join(args, " "))
		fmt.Fprintln(s.w, "ok")
	case "lookup":
		return nil, s.lookup(args)
	case "add-answer":
		return nil, s.addRR(&s.pendingAnswer, args)
	case "add-ns":
		return nil, s.addRR(&s.pendingNs, args)
	case "add-extra":
		return nil, s.addRR(&s.pendingExtra, args)
	case "pending":
		s.printPending()
	case "clear":
		s.pendingAnswer, s.pendingNs, s.pendingExtra = nil, nil, nil
		fmt.Fprintln(s.w, "cleared the pending answer/ns/extra sections")
	case "respond":
		resp, err := s.buildResponse(args)
		if err != nil {
			return nil, err
		}
		return &replResult{response: resp}, nil
	case "fail":
		msg := strings.Join(args, " ")
		if msg == "" {
			msg = "operator failed the query"
		}
		return &replResult{err: errors.New(msg)}, nil
	default:
		return nil, fmt.Errorf("unknown command %q (type %q for help)", cmd, "help")
	}
	return nil, nil
}

func (s *interactiveSession) printHelp() {
	fmt.Fprint(s.w, `commands:
  query                                  show the current query
  roothints                              list root nameservers
  trace <message>                        record a trace line for this request's log entry
  lookup <zone> <name> <qtype> <ns...>   call Helper.Lookup; each ns is "root" or host@ip
  add-answer <RR>                        add a record (zone-file format) to the pending answer section
  add-ns <RR>                            add a record to the pending authority section
  add-extra <RR>                         add a record to the pending additional section
  pending                                show the pending answer/ns/extra sections
  clear                                  discard the pending sections
  respond <rcode> [auth]                 return the pending sections as the response, e.g. "respond noerror auth"
  fail [message]                         abandon the query with an error (server responds SERVFAIL)
  help                                   show this help

RRs printed by "lookup" are already in the right format to paste into add-answer/add-ns/add-extra.
`)
}

func (s *interactiveSession) printQuery() {
	q := s.query
	fmt.Fprintf(s.w, "id=%d name=%s type=%s class=%s rd=%v client=%s proto=%s\n",
		q.ID, q.Name, dns.TypeToString[q.Type], dns.ClassToString[q.Class], q.RecursionDesired, q.ClientAddr, q.Protocol)
}

func (s *interactiveSession) printRootHints() {
	for _, ns := range s.roots {
		fmt.Fprintf(s.w, "  %s @ %s\n", ns.Name, ns.Addr)
	}
}

func (s *interactiveSession) printPending() {
	printSection(s.w, "answer", s.pendingAnswer)
	printSection(s.w, "ns", s.pendingNs)
	printSection(s.w, "extra", s.pendingExtra)
	if len(s.pendingAnswer)+len(s.pendingNs)+len(s.pendingExtra) == 0 {
		fmt.Fprintln(s.w, "(nothing pending)")
	}
}

func (s *interactiveSession) lookup(args []string) error {
	if len(args) < 4 {
		return errors.New(`usage: lookup <zone> <name> <qtype> <ns...>  (ns is "root" or host@ip)`)
	}
	zone, name, qtypeStr := args[0], args[1], args[2]

	qtype, ok := dns.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		return fmt.Errorf("unknown query type %q", qtypeStr)
	}

	var nameservers []NameServer
	for _, tok := range args[3:] {
		if strings.EqualFold(tok, "root") {
			nameservers = append(nameservers, s.roots...)
			continue
		}
		ns, err := parseNameServer(tok)
		if err != nil {
			return err
		}
		nameservers = append(nameservers, ns)
	}

	result, err := s.helper.Lookup(s.ctx, name, qtype, zone, nameservers)
	if err != nil {
		return fmt.Errorf("lookup failed: %w", err)
	}

	fmt.Fprintf(s.w, "rcode: %s\n", dns.RcodeToString[result.RCode])
	printSection(s.w, "answer", result.Answer)
	printSection(s.w, "ns", result.Ns)
	printSection(s.w, "extra", result.Extra)
	return nil
}

func (s *interactiveSession) addRR(target *[]dns.RR, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: add-answer|add-ns|add-extra <RR in zone-file format>")
	}
	rr, err := dns.NewRR(strings.Join(args, " "))
	if err != nil {
		return fmt.Errorf("invalid record: %w", err)
	}
	*target = append(*target, rr)
	fmt.Fprintf(s.w, "added: %s\n", rr.String())
	return nil
}

func (s *interactiveSession) buildResponse(args []string) (*Response, error) {
	if len(args) == 0 {
		return nil, errors.New(`usage: respond <rcode> [auth], e.g. "respond noerror auth"`)
	}
	rcode, ok := dns.StringToRcode[strings.ToUpper(args[0])]
	if !ok {
		return nil, fmt.Errorf("unknown rcode %q", args[0])
	}
	authoritative := len(args) > 1 && strings.EqualFold(args[1], "auth")

	return &Response{
		RCode:         rcode,
		Authoritative: authoritative,
		Answer:        s.pendingAnswer,
		Ns:            s.pendingNs,
		Extra:         s.pendingExtra,
	}, nil
}

func parseNameServer(tok string) (NameServer, error) {
	name, addrStr, hasName := strings.Cut(tok, "@")
	if !hasName {
		addrStr = name
		name = addrStr
	}
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return NameServer{}, fmt.Errorf("invalid nameserver %q: expected \"host@ip\" or an ip: %w", tok, err)
	}
	return NameServer{Name: dns.Fqdn(name), Addr: addr}, nil
}

func printSection(w io.Writer, label string, rrs []dns.RR) {
	if len(rrs) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", label)
	for _, rr := range rrs {
		fmt.Fprintf(w, "  %s\n", rr.String())
	}
}
