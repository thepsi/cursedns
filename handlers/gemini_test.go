package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"google.golang.org/genai"

	"cursedns/resolver"
)

// fakeGeminiTurn scripts one call's response (or error) for fakeGeminiClient.
type fakeGeminiTurn struct {
	text   string
	tokens int32
	err    error
}

// fakeGeminiClient is a deterministic, in-memory geminiClient for testing
// GeminiHandler's turn loop without ever making a real (billed) API call.
// Responses are scripted in order via turns; every call's input is decoded
// and recorded for assertions.
type fakeGeminiClient struct {
	t     *testing.T
	turns []fakeGeminiTurn

	calls  int
	inputs []geminiTurnInput
}

func (f *fakeGeminiClient) GenerateContent(ctx context.Context, model string, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	f.t.Helper()

	if len(contents) == 0 || len(contents[0].Parts) == 0 {
		f.t.Fatalf("GenerateContent called with no text content")
	}
	var input geminiTurnInput
	if err := json.Unmarshal([]byte(contents[0].Parts[0].Text), &input); err != nil {
		f.t.Fatalf("GenerateContent: turn input is not valid JSON: %v", err)
	}
	f.inputs = append(f.inputs, input)

	idx := f.calls
	f.calls++
	if idx >= len(f.turns) {
		f.t.Fatalf("GenerateContent: no scripted turn for call %d", idx)
	}
	turn := f.turns[idx]
	if turn.err != nil {
		return nil, turn.err
	}

	resp := &genai.GenerateContentResponse{
		UsageMetadata: &genai.GenerateContentResponseUsageMetadata{TotalTokenCount: turn.tokens},
	}
	if turn.text != "" {
		resp.Candidates = []*genai.Candidate{{Content: genai.NewContentFromText(turn.text, "model")}}
	}
	return resp, nil
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestGeminiHandler_DirectAnswer(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 100, text: mustJSON(t, geminiTurnResponse{
			Rationale: "root-authoritative test data answers directly",
			Action:    "answer",
			Answer: &geminiAnswer{
				RCode:   "NOERROR",
				Records: []string{"example.com. 300 IN A 93.184.216.34"},
			},
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	resp, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA, Class: dns.ClassINET}, helper)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if resp.RCode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("got RCode=%d Answer=%v, want a single A record", resp.RCode, resp.Answer)
	}
	if client.calls != 1 {
		t.Fatalf("got %d client call(s), want 1", client.calls)
	}
}

func TestGeminiHandler_ErrorAction(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 50, text: mustJSON(t, geminiTurnResponse{
			Rationale: "every nameserver failed",
			Action:    "error",
			Error:     "all nameservers failed",
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "all nameservers failed") {
		t.Fatalf("err = %v, want it to mention the model's reported error", err)
	}
}

func TestGeminiHandler_LookupThenAnswer(t *testing.T) {
	helper := newFakeHelper(t)
	helper.script("example.com.", dns.TypeA, ".", &resolver.LookupResult{
		RCode:  dns.RcodeSuccess,
		Answer: []dns.RR{mustRR(t, "example.com. 300 IN A 93.184.216.34")},
	}, nil)

	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 100, text: mustJSON(t, geminiTurnResponse{
			Rationale: "need to query root for example.com.",
			Action:    "lookup",
			Lookups: []geminiLookupRequest{
				{Name: "example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}},
			},
		})},
		{tokens: 80, text: mustJSON(t, geminiTurnResponse{
			Rationale: "root returned the answer directly",
			Action:    "answer",
			Answer:    &geminiAnswer{RCode: "NOERROR", Records: []string{"example.com. 300 IN A 93.184.216.34"}},
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test", MaxTotalLookups: 3, MaxLookupsPerTurn: 1}

	resp, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answer record(s), want 1", len(resp.Answer))
	}
	if client.calls != 2 {
		t.Fatalf("got %d client call(s), want 2", client.calls)
	}

	// The second turn's prompt must include the first lookup's result -
	// this is the core "lookups so far" requirement.
	second := client.inputs[1]
	if len(second.LookupsSoFar) != 1 {
		t.Fatalf("second turn's lookups_so_far has %d entrie(s), want 1: %+v", len(second.LookupsSoFar), second.LookupsSoFar)
	}
	record := second.LookupsSoFar[0]
	if record.Error != "" {
		t.Fatalf("recorded lookup has unexpected error: %s", record.Error)
	}
	if record.Result == nil || len(record.Result.Answer) != 1 || !strings.Contains(record.Result.Answer[0], "93.184.216.34") {
		t.Fatalf("recorded lookup result missing expected answer: %+v", record.Result)
	}

	// Budget must be visibly decreasing across turns.
	first := client.inputs[0]
	if first.Budget.TurnsRemaining <= second.Budget.TurnsRemaining {
		t.Fatalf("turns_remaining did not decrease: first=%d second=%d", first.Budget.TurnsRemaining, second.Budget.TurnsRemaining)
	}

	// The model must be told about the lookup budgets too, not just turns
	// and tokens - otherwise it has no way to avoid inadvertently
	// requesting too many lookups and having the whole query fail.
	if first.Budget.LookupsRemaining != 3 {
		t.Fatalf("first turn's lookups_remaining = %d, want the configured MaxTotalLookups (3)", first.Budget.LookupsRemaining)
	}
	if second.Budget.LookupsRemaining != 2 {
		t.Fatalf("second turn's lookups_remaining = %d, want 2 (3 minus the one lookup performed)", second.Budget.LookupsRemaining)
	}
	if first.Budget.MaxLookupsPerTurn != 1 || second.Budget.MaxLookupsPerTurn != 1 {
		t.Fatalf("max_lookups_per_turn = %d/%d, want the configured MaxLookupsPerTurn (1) on every turn", first.Budget.MaxLookupsPerTurn, second.Budget.MaxLookupsPerTurn)
	}
}

func TestGeminiResolveNameservers(t *testing.T) {
	roots := []resolver.NameServer{{Name: "a.root-servers.net.", Addr: netip.MustParseAddr("198.41.0.4")}}

	got, err := geminiResolveNameservers([]string{"root", "ns1.example.com.@192.0.2.1"}, roots)
	if err != nil {
		t.Fatalf("geminiResolveNameservers returned error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d nameserver(s), want 2: %v", len(got), got)
	}
	if got[0] != roots[0] {
		t.Fatalf("got[0] = %v, want the root hint %v", got[0], roots[0])
	}
	wantAddr := netip.MustParseAddr("192.0.2.1")
	if got[1].Addr != wantAddr || got[1].Name != "ns1.example.com." {
		t.Fatalf("got[1] = %v, want {ns1.example.com. 192.0.2.1}", got[1])
	}

	if _, err := geminiResolveNameservers([]string{"not-an-ip"}, roots); err == nil {
		t.Fatal("expected an error for an unparsable nameserver token")
	}
}

func TestGeminiHandler_UnknownQTypeRecordedAsError(t *testing.T) {
	h := &GeminiHandler{}
	helper := newFakeHelper(t)

	record := h.performLookup(context.Background(), helper, geminiLookupRequest{
		Name: "example.com.", QType: "BOGUS", Zone: ".", Nameservers: []string{"root"},
	})
	if record.Error == "" || !strings.Contains(record.Error, "unknown query type") {
		t.Fatalf("record.Error = %q, want it to mention the unknown query type", record.Error)
	}
	if record.Result != nil {
		t.Fatalf("expected no result when the qtype is unrecognized, got %+v", record.Result)
	}
}

func TestGeminiHandler_TokenBudgetExceeded(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 20, text: mustJSON(t, geminiTurnResponse{
			Rationale: "irrelevant, budget check happens first",
			Action:    "answer",
			Answer:    &geminiAnswer{RCode: "NOERROR"},
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test", MaxTokenBudget: 10}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "token budget") {
		t.Fatalf("err = %v, want a token budget error", err)
	}
}

func TestGeminiHandler_MaxTurnsExceeded(t *testing.T) {
	helper := newFakeHelper(t)
	helper.script("example.com.", dns.TypeA, ".", &resolver.LookupResult{RCode: dns.RcodeSuccess}, nil)

	lookupTurn := fakeGeminiTurn{tokens: 10, text: mustJSON(t, geminiTurnResponse{
		Rationale: "keep looking",
		Action:    "lookup",
		Lookups: []geminiLookupRequest{
			{Name: "example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}},
		},
	})}
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{lookupTurn, lookupTurn}}
	h := &GeminiHandler{Client: client, Model: "gemini-test", MaxTurns: 2}

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "maximum turns") {
		t.Fatalf("err = %v, want a maximum-turns error", err)
	}
	if client.calls != 2 {
		t.Fatalf("got %d client call(s), want exactly MaxTurns (2)", client.calls)
	}
}

func TestGeminiHandler_LookupsPerTurnLimitExceeded(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 10, text: mustJSON(t, geminiTurnResponse{
			Rationale: "asking for two at once",
			Action:    "lookup",
			Lookups: []geminiLookupRequest{
				{Name: "a.example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}},
				{Name: "b.example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}},
			},
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test", MaxLookupsPerTurn: 1}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "exceeding the limit") {
		t.Fatalf("err = %v, want a per-turn lookup limit error", err)
	}
}

func TestGeminiHandler_TotalLookupBudgetExceeded(t *testing.T) {
	helper := newFakeHelper(t)
	helper.script("a.example.com.", dns.TypeA, ".", &resolver.LookupResult{RCode: dns.RcodeSuccess}, nil)

	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 10, text: mustJSON(t, geminiTurnResponse{
			Rationale: "first lookup",
			Action:    "lookup",
			Lookups:   []geminiLookupRequest{{Name: "a.example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}}},
		})},
		{tokens: 10, text: mustJSON(t, geminiTurnResponse{
			Rationale: "second lookup, should be refused by the total budget",
			Action:    "lookup",
			Lookups:   []geminiLookupRequest{{Name: "b.example.com.", QType: "A", Zone: ".", Nameservers: []string{"root"}}},
		})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test", MaxTotalLookups: 1}

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "total lookup budget") {
		t.Fatalf("err = %v, want a total lookup budget error", err)
	}
}

func TestGeminiHandler_MalformedJSONResponse(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 10, text: "this is not json"},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "parse model response") {
		t.Fatalf("err = %v, want a JSON parse error", err)
	}
}

func TestGeminiHandler_UnknownAction(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 10, text: mustJSON(t, geminiTurnResponse{Rationale: "?", Action: "frobnicate"})},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("err = %v, want an unknown-action error", err)
	}
}

func TestGeminiHandler_EmptyResponseTreatedAsError(t *testing.T) {
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{
		{tokens: 5, text: ""},
	}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if err == nil {
		t.Fatal("expected an error for an empty model response, got nil")
	}
}

func TestGeminiHandler_ClientErrorPropagates(t *testing.T) {
	wantErr := errors.New("upstream unavailable")
	client := &fakeGeminiClient{t: t, turns: []fakeGeminiTurn{{err: wantErr}}}
	h := &GeminiHandler{Client: client, Model: "gemini-test"}
	helper := newFakeHelper(t)

	_, err := h.Handle(context.Background(), resolver.Query{Name: "example.com.", Type: dns.TypeA}, helper)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want it to wrap %v", err, wantErr)
	}
}
