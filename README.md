# cursedns

A skeleton recursive DNS server. It handles the networking (UDP/TCP,
parsing, SERVFAIL on error/timeout) and hands each query to a pluggable
`resolver.Handler`.

## Build

```sh
go build -o cursedns .
```

The examples below use port 8053 rather than cursedns's actual default
(5353), since 5353 is the standard mDNS port and is commonly already bound
by something like `avahi-daemon` or `systemd-resolved`.

## Run with the static handler

The static handler is a dummy that answers every A/AAAA query with a fixed
address. It's the default, so no `-handler` flag is needed:

```sh
./cursedns -listen 127.0.0.1:8053
```

Query it:

```sh
dig @127.0.0.1 -p 8053 example.com A +short
```

## Run with the interactive handler

The interactive handler lets a human resolve each query by hand at this
terminal (see `resolver/interactive.go` for the full command list: `query`,
`roothints`, `lookup`, `add-answer`/`add-ns`/`add-extra`, `respond`, `fail`,
`help`). The server automatically raises its default per-request timeout to
5 minutes in this mode, since a human needs longer than the 5s default
aimed at automated handlers:

```sh
./cursedns -listen 127.0.0.1:8053 -handler interactive
```

In another terminal, query it. `dig` normally gives up (and retries) after
5 seconds, which is far too short to answer by hand, so extend its timeout
and disable retries:

```sh
dig @127.0.0.1 -p 8053 +timeout=120 +tries=1 example.com A
```

Back in the server's terminal you'll see the query printed, followed by a
`>` prompt where you can type commands, e.g.:

```
> add-answer example.com. 300 IN A 203.0.113.7
> respond noerror
```

`dig` will then print the record you supplied.

## Run with the recursive handler

The recursive handler performs real iterative resolution: starting from the
IANA root hints, it follows delegations down to an authoritative answer,
following CNAME chains and bailiwick-checking every referral and glue record
along the way. Unlike the other two handlers, this one makes genuine queries
out to the live DNS:

```sh
./cursedns -listen 127.0.0.1:8053 -handler recursive
```

Query it like any other resolver:

```sh
dig @127.0.0.1 -p 8053 example.com A +short
```

Query it again for the same name and you should see a faster response, since
the answer (and the delegation chain used to reach it) are now cached.

## Run with the Gemini handler

The Gemini handler hands each query to the Gemini API: the model is given the
question and the results of every lookup performed so far, as JSON, and must
respond with either a final answer, an error, or a request to perform further
lookups before being consulted again. Set an API key first:

```sh
export GEMINI_API_KEY=...   # or GOOGLE_API_KEY
./cursedns -listen 127.0.0.1:8053 -handler gemini
```

`-gemini-model`, `-gemini-max-turns`, and `-gemini-max-tokens` override the
model name and the per-request turn/token budget (see `-help` for defaults).
Every request is charged real, billed API usage and makes genuine queries out
to the live DNS - unlike the other handlers here, **this one was not
exercised against the real API or the live DNS** while building it, only
against a fake, in-process client in `resolver/gemini_test.go`, per the
instruction not to risk a costly bug during development. Test it cautiously
the first time you run it for real.

## Trace lookup

Any handler can optionally have its per-request trace detail (the same
information logged to `request completed`) stashed in memory and fetched
back later over HTTP - useful when a `dig` in one terminal doesn't show
enough, and you want the full hop-by-hop story afterward. It's off by
default; turn it on with:

```sh
./cursedns -listen 127.0.0.1:8053 -handler recursive \
  -trace-http-listen 127.0.0.1:8080 -trace-capacity 1000
```

When enabled, every response gets a synthetic TXT record appended to its
Additional section, owned by the fixed, non-resolvable name
`_cursedns-trace.invalid.` (under the `.invalid` TLD reserved by RFC 2606,
so it can never be confused with real, cacheable DNS data), with TTL 0 and
content set to that request's trace ID:

```sh
dig @127.0.0.1 -p 8053 example.com A +additional
# ...
# _cursedns-trace.invalid. 0 IN TXT "a1b2c3...

curl http://127.0.0.1:8080/trace/a1b2c3...
```

The `-trace-capacity` most recent traces are kept, least-recently-used
first to be evicted once full. Enabling this adds roughly 60-90 bytes to
every response's Additional section, which could push a response that was
previously just under a tight UDP size budget into truncation (TC bit set,
client retries over TCP) where it wouldn't have been before.

**Security note:** the trace HTTP endpoint is unauthenticated and returns
full internal resolution detail - every nameserver contacted and the timing
of each step - for any trace ID presented to it. The only thing standing
between a curious third party and another client's query history is that
trace IDs are unguessable (128 bits of randomness, revealed only to whoever
received that specific response). That's fine for local development, but
think carefully before enabling this on a shared or multi-tenant resolver -
bind `-trace-http-listen` to localhost, or don't enable it at all.

## TODO

Known gaps in the recursive handler, deferred for now:

- **Truncation / TCP fallback for outbound queries.** `requestHelper.Lookup`
  sends plain UDP queries to upstream nameservers with no EDNS0 OPT record
  and never checks the response's TC bit, so a reply too big for a bare
  512-byte UDP response is silently truncated instead of being retried over
  TCP. This is a correctness gap, not just an optimization.
- **Cache-shortcutting past root.** `RecursiveHandler` always starts
  iteration at the root hints, even when a deeper zone's nameservers are
  already cached from a previous query. Skipping straight to the deepest
  known zone would meaningfully cut root/TLD server load on repeat queries,
  at the cost of extra complexity (resolving cached NS names back to
  addresses).
- **Nameserver order/anti-spoofing hardening.** Nameservers within a
  referral are always tried in the same, deterministic order, and outbound
  queries don't use 0x20-encoding of the query name - both are common
  real-resolver defenses/load-spreading techniques not implemented here.

Known gap in the Gemini handler:

- **Zone-trust validation for model-requested lookups.** Like the
  interactive handler, the Gemini handler trusts whatever `zone` the caller
  (here, the model) asserts for a lookup - `Helper.Lookup`'s bailiwick
  checking is only as good as that assertion. A human operator typing a
  wrong zone is one thing; the model's next action is influenced by content
  it has read out of previous lookup results, including raw data from
  nameservers on the path to the answer, so a malicious upstream could in
  principle attempt to talk the model into asserting a broader zone than it
  actually observed (a DNS-flavored prompt injection). Consider having the
  harness independently derive/validate zones from observed delegations
  (as `RecursiveHandler` does) rather than trusting the model's stated zone
  outright.
