# DNS Tunnel Query Type: SRV — Design

**Date:** 2026-09-11
**Status:** Approved in chat (brainstorming session: "add SRV dns record support"; path classified architectural; open decisions confirmed: NS-style multi-record framing, 4-way ROTATE)
**Goal:** Let the StormDNS VPN-over-DNS tunnel speak SRV record type in addition to TXT, NS, and CNAME, so the tunnel works when those types are blocked, mangled, or fingerprinted in the resolver path and so the query stream can be disguised by mixing all four types (`ROTATE`).

## Background

`DNS_QUERY_TYPE` already selects the tunnel query type: `"TXT"` (default), `"NS"`, `"CNAME"`, or `"ROTATE"` (uniform random TXT/NS/CNAME per query). The server mirrors the question type: an NS question gets NS answers, a CNAME question gets CNAME answer chains, and payload units ride in the rdata domain name (lowercase-base36 text split into ≤63-char labels). `DNS_RECORD_TYPE_SRV = 33` and `DNSRecordTypeName("SRV")` already exist; `IsSupportedTunnelDNSQuery` (relay/proxy policy) already accepts SRV. Nothing else touches SRV.

SRV is the next transport in this line because its rdata has six fixed bytes (`priority`, `weight`, `port`) before the target name, and (unlike CNAME) RFC 2782 explicitly allows many SRV records per owner name.

## Design Decisions (locked)

1. **Transport, not discovery.** SRV support means a tunnel query/answer record type mirrored by the server, exactly like NS/CNAME. It is not server auto-discovery and not serving real SRV data. No server config.

2. **Six fixed bytes carry payload.** An SRV rdata is `priority(2) weight(2) port(2) target`. The tunnel unit is packed as: first 6 unit bytes → the three fields (big-endian, in that order); remaining unit bytes → lowercase-base36 target wire name (labels ≤63 chars, same rules as NS/CNAME). Extraction reconstructs `unit = RData[0:6] || decodeLowerBase36(RDataName)`. The six bytes are mandatory in every SRV record, so carrying payload there is free wire capacity (no new fields), and the field values look pseudo-random rather than all-zero.

3. **Unit capacities (verified against `basecodec`).**
   - `maxNSUnitBytes()` = **159** (`EncodedLenLowerBase36(159) = 250 = maxNSNameChars`; 160 → 252). The stale "~161 bytes" comment in `transport.go` is corrected to 159 (comment-only).
   - `maxSRVUnitBytes()` = `maxNSUnitBytes() + 6` = **165**.
   - Wire per fully packed record: NS/CNAME ≈ 2 (owner pointer) + 10 + 255 (name = 250 chars + 4 label-length bytes + 1 terminator) = 267 B for 159 payload (59.6%); SRV ≈ 2 + 10 + (6 + 255) = 273 B for 165 payload (60.4%). Records needed for a frame of P bytes: `ceil(P/159)` vs `ceil(P/165)` (≈3.8% fewer). Net downlink saving is ≈1.5% on average, up to ≈15% when a frame crosses a record-count boundary (e.g. 800 B: 6 records → 5); equal record counts can cost ≈2% more. This is a modest but real efficiency gain; the primary benefit is not wasting mandatory rdata bytes.

4. **Multi-unit framing is NS-style.** One SRV RR per unit; every record owns the query name (first record writes the full qname, later records use a 2-byte compression pointer to it), exactly like `BuildNSResponsePacket`. RFC 2782 allows many SRV records per owner, so no CNAME-style chain is needed. The existing unit chunk layout is unchanged: chunk 0 = `[0x00][total][vpn header][payload...]`, chunk N = `[id][payload...]`. Chunk IDs make resolver reordering harmless.

5. **Every unit is ≥ 6 bytes by construction.** The decoder rule `unit = RData[0:6] || nameBytes` can only recover units of length exactly 6 (all six bytes in the fields, root target) or > 6. A unit of 1–5 bytes would be ambiguous, so the SRV chunker guarantees it never emits one:
   - Chunk 0 is always ≥ 6 bytes (2 prefix + ≥4-byte VPN header).
   - The final chunk unit is rebalanced to ≥ 6 bytes when the natural split would make it 2–5 (move bytes from the previous, full chunk). Non-final chunks are full.
   - Single-unit frames (≤165 B) encode directly; `len(rawFrame) == 6` yields a root target, which is legal RFC 2782 ("service not available") and decodes to exactly 6 bytes.
   - Degenerate fallback: a single-unit frame shorter than 6 bytes (cannot be produced by a valid VPN packet: minimum header is 4 bytes and chunk 0 framing is not involved, but the guard is cheap) is answered NS-style. The client extractor is per-answer-type already, so it reads the NS unit. No silent padding ever happens.

6. **Root target is decoded exactly.** For SRV, the parser decodes the target name starting at rdata offset 6 (after `priority/weight/port`), unlike NS/CNAME (offset 0). A root target leaves `RDataName == ""` (no error). Extraction accepts a root target only as the exact shape `len(RData) == 7 && RData[6] == 0` → unit = `RData[:6]`; any other undecodable SRV rdata is skipped (same tolerance as today's malformed NS/CNAME handling). Decode failures never fail packet parsing (the relay path must not break on weird answers).

7. **Extraction is type-aware.** `extractAnswerUnits` keeps its contract: name-type answers (NS/CNAME/SRV) are base36-decoded first and TXT is ignored when any name-type unit is present; the `baseEncoded` session flag applies to TXT answers only (unchanged behavior). Per-type unit decode:
   - NS/CNAME: `decodeLowerBase36(RDataName)`, skip empty/undecodable.
   - SRV: `RData[:6] || decodeLowerBase36(RDataName)`, root-target special case as above.

8. **Client config and ROTATE.** `DNS_QUERY_TYPE` accepts `"SRV"`; `ROTATE` becomes uniform 4-way (`rand.Intn(4)`: TXT/NS/CNAME/SRV). ROTATE already assumes the path and server support every listed type (it includes CNAME today); adding SRV does not change that contract. Session init retries and ARQ retransmission absorb lost queries as for the existing types.

9. **No changes to TXT/NS/CNAME semantics.** New SRV builders and branches sit alongside the existing ones. The only shared-code change is extracting the unit-chunking core of `buildNSAnswerChunks` into a shared helper (`buildNameAnswerUnits`), with `buildNSAnswerChunks` kept as a thin wrapper whose behavior is byte-identical (existing NS/CNAME tests are the regression lock). TXT code paths are untouched.

10. **Compatibility.** An old server answers SRV tunnel queries with NODATA (`unsupported-qtype` matcher rejection), surfacing as the existing session-init retry failure — same as CNAME. TXT/NS/CNAME/ROTATE-3 (old client) keep working against the new server. No wire negotiation. Documented in the config sample and README, with "update server first" guidance.

11. **No new exported symbols** in `enums`, `vpnproto`, `basecodec`. New helpers in `dnsparser` are unexported except the response builders that follow the existing exported pattern (`BuildSRVResponsePacket`, mirroring `BuildNSResponsePacket`).

## Component Changes

| File | Change |
|------|--------|
| `internal/dnsparser/parser.go` | `nameRDataNameOffset(recordType) int` (NS/CNAME → 0, SRV → 6, else −1); use it in `parseResourceRecords` instead of `isNameRDataRecordType`; update `RDataName` field comment to mention SRV |
| `internal/dnsparser/transport.go` | `maxSRVUnitBytes()`; `buildSRVAnswerRData(unit)`; `buildSRVAnswerRDatas(rawFrame)`; `questionTypeIsSRV`; `buildSingleSRVResponsePacket`; `BuildSRVResponsePacket`; `buildSRVVPNResponse` + dispatch branch in `BuildVPNResponsePacket`; `buildNameAnswerUnits(rawFrame, maxUnit, minUnit)` shared chunker with `buildNSAnswerChunks` wrapper; per-type unit decode in `extractAnswerUnits` (NS/CNAME/SRV + root-target case); fix stale 159/161 comment |
| `internal/dnsparser/srv_test.go` (new) | Parser decode (offset 6, compression, garbage, root) and transport round-trips (single, multi, boundary rebalance, root-target unit, appended records, base64-flag irrelevance, malformed) |
| `internal/domainmatcher/matcher.go` (+ test) | Accept SRV in the `ActionProcess` qtype gate (mirror of NS/CNAME) |
| `internal/config/client.go` (+ test) | `DNS_QUERY_TYPE` validation accepts `"SRV"` |
| `internal/client/tunnel_query.go` (+ test) | `"SRV"` → type 33; `ROTATE` → uniform `rand.Intn(4)` |
| `internal/udpserver/srv_tunnel_test.go` (new) | End-to-end: matcher accepts SRV tunnel query → MTU handler builds multi-record SRV answer → `ExtractVPNResponse` recovers payload; mirrors `cname_tunnel_test.go` |
| `client_config.toml.simple` | `DNS_QUERY_TYPE` comment block: add `"SRV"`, update `"ROTATE"` to TXT/NS/CNAME/SRV |
| `README.MD` | Delegation details: SRV row in the `DNS_QUERY_TYPE` table, ROTATE description, "requires matching server" note, FAQ transport-fallback sentence |

`internal/dnsparser/policy.go` already accepts SRV — no change. Server config — no change.

## Error Handling / Edge Cases

- Malformed/undecodable SRV rdata (name overruns `rdlen`, bad labels, `rdlen < 6`): leave `RDataName` empty and never fail `ParsePacket`; extraction skips the record. Missing/duplicate chunks still surface as `ErrTXTAnswerMalformed` → existing retry.
- Corruption of field bytes: identical exposure to any other tunnel byte. Methods 3–5 (AES-GCM) authenticate and reject; methods 0/1/2 (none/XOR/ChaCha20) rely on the same parse/checksum paths already in use. No new failure mode.
- Resolver reordering SRV RRsets (RFC 2782 sorting): harmless — chunk IDs order reassembly.
- Resolver dropping/mangling SRV: transport unavailable → user switches mode, exactly the failure class NS/CNAME exist to route around.
- `len(rawFrame) < 6` single-unit degenerate: NS-style fallback (decision 5).

## Testing Strategy

TDD per task, following the CNAME change pattern:

1. **Parser:** SRV target decoded at offset 6 (plain and compression-pointer rdata), garbage rdata tolerated, root target → `RDataName == ""`; NS/CNAME tests unchanged.
2. **Transport:** single-unit round-trip; multi-unit round-trip with owners resolving to the qname and every unit ≥ 6 bytes; boundary barrage (payload lengths 0..~1500) asserting exact round-trip and the rebalance/root-target cases; appended-extra-record tolerance; `baseEncoded=true` does not affect SRV; malformed SRV → `ErrTXTAnswerMissing`; capacity assertion `maxSRVUnitBytes() == maxNSUnitBytes()+6`.
3. **Matcher/config/client:** SRV accepted as `ActionProcess`; `DNS_QUERY_TYPE="srv"` normalizes to `"SRV"`; SRV mode builds qtype 33 packets; ROTATE produces all four types.
4. **Integration:** `udpserver` end-to-end SRV test with a payload large enough to force multiple records.
5. **Regression:** `go vet ./...`, `go build ./cmd/client && go build ./cmd/server`, `go test ./...`, `go test -race` on the touched packages. Optional local bench smoke.

## Risks

- A middlebox that *rewrites* `priority/weight/port` (rather than reorders) corrupts the unit; authenticated encryption (methods 3–5) turns that into a normal retransmit. This is the accepted cost of using the six bytes for payload; the alternative costs capacity.
- A resolver that drops or specially processes SRV queries makes this mode unusable on that path — the reason multiple transport types exist.
- Stale assumption risk: capacity math is pinned by tests (`maxSRVUnitBytes()`), so future base36 changes cannot silently invalidate it.

## Out of Scope

- Configurable ROTATE type list; SRV-based server discovery; serving genuine SRV records; HTTPS/SVCB/NAPTR transports; query-side (uplink) encoding changes.
