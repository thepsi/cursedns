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
