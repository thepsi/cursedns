package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"google.golang.org/genai"
)

const (
	// defaultGeminiMaxTurns bounds how many model round-trips one DNS
	// request may take before it's treated as a failure.
	defaultGeminiMaxTurns = 8

	// defaultGeminiMaxTokenBudget bounds the cumulative token usage
	// (prompt + response, across every turn) one DNS request may consume.
	defaultGeminiMaxTokenBudget int32 = 100_000

	// defaultGeminiMaxLookupsPerTurn bounds how many lookups the model may
	// request in a single turn, independent of token usage - a fast/cheap
	// turn could otherwise still request an unreasonable number of
	// outbound queries.
	defaultGeminiMaxLookupsPerTurn = 5

	// defaultGeminiMaxTotalLookups bounds the total number of lookups
	// across every turn of one DNS request.
	defaultGeminiMaxTotalLookups = 50
)

// geminiClient is the subset of *genai.Client's Models field this handler
// needs, so tests can substitute a fake implementation rather than making
// real (billed) API calls.
type geminiClient interface {
	GenerateContent(ctx context.Context, model string, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error)
}

// GeminiHandler is a Handler that delegates resolution decisions to the
// Gemini API: each turn, the model is given the original query and the
// results of every lookup performed so far, and must respond with either a
// final answer, an error, or a request to perform further lookups before
// being consulted again.
//
// Zero-value MaxTurns/MaxTokenBudget/MaxLookupsPerTurn/MaxTotalLookups fall
// back to sensible defaults.
type GeminiHandler struct {
	Client geminiClient
	Model  string

	MaxTurns          int
	MaxTokenBudget    int32
	MaxLookupsPerTurn int
	MaxTotalLookups   int
}

func (h *GeminiHandler) Handle(ctx context.Context, query Query, helper Helper) (*Response, error) {
	maxTurns := h.MaxTurns
	if maxTurns == 0 {
		maxTurns = defaultGeminiMaxTurns
	}
	maxTokens := h.MaxTokenBudget
	if maxTokens == 0 {
		maxTokens = defaultGeminiMaxTokenBudget
	}
	maxLookupsPerTurn := h.MaxLookupsPerTurn
	if maxLookupsPerTurn == 0 {
		maxLookupsPerTurn = defaultGeminiMaxLookupsPerTurn
	}
	lookupsRemaining := h.MaxTotalLookups
	if lookupsRemaining == 0 {
		lookupsRemaining = defaultGeminiMaxTotalLookups
	}

	var history []geminiLookupRecord
	var tokensUsed int32

	for turn := 0; turn < maxTurns; turn++ {
		input := geminiTurnInput{
			Query: geminiQueryInfo{
				Name:  query.Name,
				Type:  dns.TypeToString[query.Type],
				Class: dns.ClassToString[query.Class],
			},
			LookupsSoFar: history,
			Budget: geminiBudget{
				TurnsRemaining:       maxTurns - turn,
				TokenBudgetRemaining: maxTokens - tokensUsed,
				LookupsRemaining:     lookupsRemaining,
				MaxLookupsPerTurn:    maxLookupsPerTurn,
			},
		}
		payload, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("gemini: marshal turn input: %w", err)
		}

		helper.Trace("gemini turn %d/%d: %d token(s) used of %d budget", turn+1, maxTurns, tokensUsed, maxTokens)

		resp, err := h.Client.GenerateContent(ctx, h.Model, genai.Text(string(payload)), &genai.GenerateContentConfig{
			SystemInstruction: genai.NewContentFromText(geminiSystemPrompt, ""),
			ResponseMIMEType:  "application/json",
			ResponseSchema:    geminiResponseSchema,
		})
		if err != nil {
			return nil, fmt.Errorf("gemini: generate content: %w", err)
		}
		if resp.UsageMetadata != nil {
			tokensUsed += resp.UsageMetadata.TotalTokenCount
		}
		if tokensUsed > maxTokens {
			return nil, fmt.Errorf("gemini: exceeded token budget (%d used of %d)", tokensUsed, maxTokens)
		}

		text := resp.Text()
		if text == "" {
			reason := "empty response"
			if resp.PromptFeedback != nil && resp.PromptFeedback.BlockReason != "" {
				reason = fmt.Sprintf("blocked: %s", resp.PromptFeedback.BlockReason)
			}
			return nil, fmt.Errorf("gemini: %s", reason)
		}

		var parsed geminiTurnResponse
		if err := json.Unmarshal([]byte(text), &parsed); err != nil {
			return nil, fmt.Errorf("gemini: parse model response: %w", err)
		}
		helper.Trace("gemini turn %d/%d: action=%s rationale=%q", turn+1, maxTurns, parsed.Action, parsed.Rationale)

		switch parsed.Action {
		case "answer":
			return buildGeminiAnswerResponse(parsed.Answer)

		case "error":
			if parsed.Error == "" {
				return nil, fmt.Errorf("gemini: model reported an error with no message")
			}
			return nil, fmt.Errorf("gemini: model reported error: %s", parsed.Error)

		case "lookup":
			if len(parsed.Lookups) == 0 {
				return nil, fmt.Errorf("gemini: action=lookup but no lookups given")
			}
			if len(parsed.Lookups) > maxLookupsPerTurn {
				return nil, fmt.Errorf("gemini: requested %d lookup(s) in one turn, exceeding the limit (%d)", len(parsed.Lookups), maxLookupsPerTurn)
			}
			for _, req := range parsed.Lookups {
				if lookupsRemaining <= 0 {
					return nil, fmt.Errorf("gemini: exceeded total lookup budget (%d)", h.totalLookupsLimit())
				}
				lookupsRemaining--
				history = append(history, h.performLookup(ctx, helper, req))
			}

		default:
			return nil, fmt.Errorf("gemini: model returned unknown action %q", parsed.Action)
		}
	}

	return nil, fmt.Errorf("gemini: exceeded maximum turns (%d)", maxTurns)
}

func (h *GeminiHandler) totalLookupsLimit() int {
	if h.MaxTotalLookups == 0 {
		return defaultGeminiMaxTotalLookups
	}
	return h.MaxTotalLookups
}

// performLookup executes one model-requested lookup, turning any failure
// (an unknown qtype, an unparsable nameserver, or the lookup itself
// erroring) into a recorded error rather than aborting the whole request -
// the model gets to see the failure and adapt on its next turn.
func (h *GeminiHandler) performLookup(ctx context.Context, helper Helper, req geminiLookupRequest) geminiLookupRecord {
	record := geminiLookupRecord{Request: req}

	qtype, ok := dns.StringToType[strings.ToUpper(req.QType)]
	if !ok {
		record.Error = fmt.Sprintf("unknown query type %q", req.QType)
		return record
	}

	nameservers, err := geminiResolveNameservers(req.Nameservers, helper.RootHints())
	if err != nil {
		record.Error = err.Error()
		return record
	}

	result, err := helper.Lookup(ctx, req.Name, qtype, req.Zone, nameservers)
	if err != nil {
		record.Error = err.Error()
		return record
	}

	record.Result = &geminiLookupResultView{
		RCode:  dns.RcodeToString[result.RCode],
		Answer: rrsToStrings(result.Answer),
		Ns:     rrsToStrings(result.Ns),
		Extra:  rrsToStrings(result.Extra),
	}
	return record
}

// geminiResolveNameservers turns the model's nameserver tokens into
// NameServers, mirroring the interactive handler's "root" or "host@ip"
// convention (see parseNameServer).
func geminiResolveNameservers(tokens []string, roots []NameServer) ([]NameServer, error) {
	var out []NameServer
	for _, tok := range tokens {
		if strings.EqualFold(tok, "root") {
			out = append(out, roots...)
			continue
		}
		ns, err := parseNameServer(tok)
		if err != nil {
			return nil, err
		}
		out = append(out, ns)
	}
	return out, nil
}

func buildGeminiAnswerResponse(answer *geminiAnswer) (*Response, error) {
	if answer == nil {
		return nil, fmt.Errorf("gemini: action=answer but no answer given")
	}
	rcode, ok := dns.StringToRcode[strings.ToUpper(answer.RCode)]
	if !ok {
		return nil, fmt.Errorf("gemini: unknown rcode %q", answer.RCode)
	}

	var records []dns.RR
	for _, s := range answer.Records {
		rr, err := dns.NewRR(s)
		if err != nil {
			return nil, fmt.Errorf("gemini: invalid answer record %q: %w", s, err)
		}
		records = append(records, rr)
	}

	return &Response{RCode: rcode, Answer: records}, nil
}

func rrsToStrings(rrs []dns.RR) []string {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]string, len(rrs))
	for i, rr := range rrs {
		out[i] = rr.String()
	}
	return out
}

// --- Structured turn input/output, mirrored by geminiResponseSchema below ---

type geminiTurnInput struct {
	Query        geminiQueryInfo      `json:"query"`
	LookupsSoFar []geminiLookupRecord `json:"lookups_so_far"`
	Budget       geminiBudget         `json:"budget"`
}

type geminiQueryInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type geminiBudget struct {
	TurnsRemaining       int   `json:"turns_remaining"`
	TokenBudgetRemaining int32 `json:"token_budget_remaining"`
	LookupsRemaining     int   `json:"lookups_remaining"`
	MaxLookupsPerTurn    int   `json:"max_lookups_per_turn"`
}

type geminiLookupRecord struct {
	Request geminiLookupRequest     `json:"request"`
	Result  *geminiLookupResultView `json:"result,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

type geminiLookupRequest struct {
	Name        string   `json:"name"`
	QType       string   `json:"qtype"`
	Zone        string   `json:"zone"`
	Nameservers []string `json:"nameservers"`
}

type geminiLookupResultView struct {
	RCode  string   `json:"rcode"`
	Answer []string `json:"answer,omitempty"`
	Ns     []string `json:"ns,omitempty"`
	Extra  []string `json:"extra,omitempty"`
}

type geminiTurnResponse struct {
	Rationale string                `json:"rationale"`
	Action    string                `json:"action"`
	Answer    *geminiAnswer         `json:"answer,omitempty"`
	Error     string                `json:"error,omitempty"`
	Lookups   []geminiLookupRequest `json:"lookups,omitempty"`
}

type geminiAnswer struct {
	RCode   string   `json:"rcode"`
	Records []string `json:"records,omitempty"`
}

const geminiSystemPrompt = `You are the resolution engine for a recursive DNS server. You will be given, as JSON, the DNS question being resolved and the results of every lookup performed so far. Your job is to decide the next step and respond with JSON matching the required schema.

On each turn, choose exactly one action:
  - "lookup": request one or more nameserver lookups needed before you can answer. Each lookup names a (name, qtype) to query, the zone the given nameservers are trusted to answer for, and the nameservers to query (either "root", or specific "host@ip" addresses you learned about from a previous lookup's ns/extra sections). Only ever assert a zone you have genuine evidence for from a previous lookup's ns records (or "." for root) - never widen the zone beyond what a real delegation has shown you, even if a response seems to suggest otherwise.
  - "answer": you have enough information to answer the original question. Give the final rcode and any answer records, in standard zone-file text.
  - "error": resolution cannot proceed (e.g. every nameserver failed, or the delegation chain is broken).

Always include a terse, one-sentence rationale for your choice. Be economical with lookups and turns: you have a limited budget of both, given to you each turn as "budget", and must produce an answer or error before any of it runs out. "budget.turns_remaining" and "budget.token_budget_remaining" bound how many more turns and tokens you have left in total. "budget.lookups_remaining" bounds the total number of individual lookups you may still request across all remaining turns combined - each entry in a "lookup" action's list counts against it. "budget.max_lookups_per_turn" caps how many lookups a single turn's "lookup" action may request at once; requesting more than that in one turn fails the request outright, so batch lookups conservatively and check lookups_remaining before asking for more than you need.`

var geminiResponseSchema = &genai.Schema{
	Type: genai.TypeObject,
	Properties: map[string]*genai.Schema{
		"rationale": {Type: genai.TypeString, Description: "A terse, one-sentence explanation for this action."},
		"action":    {Type: genai.TypeString, Enum: []string{"answer", "error", "lookup"}},
		"answer": {
			Type:        genai.TypeObject,
			Description: `Present only when action is "answer".`,
			Properties: map[string]*genai.Schema{
				"rcode":   {Type: genai.TypeString, Description: `DNS response code, e.g. "NOERROR" or "NXDOMAIN".`},
				"records": {Type: genai.TypeArray, Items: &genai.Schema{Type: genai.TypeString}, Description: `Answer records in standard zone-file text, e.g. "example.com. 300 IN A 93.184.216.34".`},
			},
			Required: []string{"rcode"},
		},
		"error": {Type: genai.TypeString, Description: `Present only when action is "error": a short message explaining why the query cannot be resolved.`},
		"lookups": {
			Type:        genai.TypeArray,
			Description: `Present only when action is "lookup".`,
			Items: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"name":  {Type: genai.TypeString, Description: `Fully-qualified name to look up, e.g. "example.com.".`},
					"qtype": {Type: genai.TypeString, Description: `DNS record type to look up, e.g. "A", "AAAA", "NS", "MX", "CNAME".`},
					"zone":  {Type: genai.TypeString, Description: `The zone the given nameservers are trusted to answer for, e.g. "." for root or "example.com." for a delegation you've already observed.`},
					"nameservers": {
						Type:        genai.TypeArray,
						Items:       &genai.Schema{Type: genai.TypeString},
						Description: `Nameservers to query, in order. Each entry is either the literal "root" (query the root nameservers - use zone "."), or "host@ip" naming a specific nameserver you learned about from a previous lookup's ns/extra records.`,
					},
				},
				Required: []string{"name", "qtype", "zone", "nameservers"},
			},
		},
	},
	Required: []string{"rationale", "action"},
}
