# DNS Tunnel Query Type: SRV — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the StormDNS VPN-over-DNS tunnel speak SRV record type in addition to TXT, NS, and CNAME, so the tunnel works when those types are blocked, mangled, or fingerprinted in the resolver path and so the query stream can be disguised by mixing all four types (`ROTATE`).

**Architecture:** Same mirror rule as NS/CNAME: the server answers SRV questions with SRV answers. Each transport unit is packed as six raw bytes in the mandatory `priority`/`weight`/`port` rdata fields plus the remainder as a lowercase-base36 target wire name (the name transport shared with NS/CNAME). Multi-unit answers use the NS shape — one SRV RR per unit, all owning the qname (later owners compressed) — because RFC 2782 allows many SRV records per owner. The client picks the qtype per query from config: `TXT` (default), `NS`, `CNAME`, `SRV`, or `ROTATE` (uniform random over the four).

**Tech Stack:** Go (repo `go.mod`), existing `internal/dnsparser`, `internal/basecodec` (lowerbase36), `internal/domainmatcher`, `internal/config`, `internal/client`, `internal/udpserver`, `internal/vpnproto`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-11-dns-tunnel-query-type-srv-design.md`

## Design Decisions (locked, from the spec)

1. SRV is a tunnel transport (server mirrors qtype), not server discovery. No server config, no wire negotiation.
2. The 6 mandatory SRV rdata bytes carry payload: `unit = 6 fixed bytes || base36(target name)`. Extraction rebuilds `unit = RData[0:6] || decodeLowerBase36(RDataName)`.
3. Capacities (verified): `maxNSUnitBytes() == 159` (`EncodedLenLowerBase36(159) == 250`); `maxSRVUnitBytes() == 165`. Fix the stale "~161" comment.
4. Multi-unit framing is NS-style: all SRV RRs own the qname, later owners use a 2-byte compression pointer. Chunk layout is unchanged (`[0x00][total][header][payload...]` / `[id][payload...]`).
5. Every transport unit is ≥ 6 bytes by construction. The SRV chunker rebalances the final chunk upward (move the deficit from the previous full chunk) so no 1–5-byte unit exists. A 6-byte unit encodes as six fixed bytes + a root target; extraction accepts root only as exactly `len(RData) == 7 && RData[6] == 0`. A degenerate single frame shorter than 6 bytes (not producible by a valid VPN packet) falls back to an NS-style answer; the extractor is per-answer-type.
6. Parser decodes SRV target names at rdata offset 6 (NS/CNAME at 0). Decode failures and short rdata leave `RDataName` empty and never fail packet parsing.
7. Extraction is type-aware: name-type answers (NS/CNAME/SRV) are base36-decoded first and TXT is ignored when any name unit is present; `baseEncoded` applies to TXT only, as today.
8. `ROTATE` becomes uniform 4-way (`rand.Intn(4)`).
9. TXT/NS/CNAME semantics untouched. The only shared-code change is extracting the chunk core of `buildNSAnswerChunks` into `buildNameAnswerUnits`; the NS wrapper stays byte-identical (existing tests are the regression lock).
10. Old server answers SRV with NODATA → existing session-init retry failure; docs say update the server first.
11. No new exported symbols in `enums`, `vpnproto`, `basecodec`. `BuildSRVResponsePacket` follows the existing exported-builder pattern.

## Global Constraints

- DNS name wire length limit: 250 text chars for rdata names (labels ≤63; worst 4-label split = 250+4+1 = 255 ≤ 255). Never emit a 251-char text.
- Only lowercase-base36 (`[0-9a-z]`) may appear in SRV target labels.
- SRV target-name compression is never written by the server (full names + root only); the parser still resolves pointers for robustness.
- Do not change TXT/NS/CNAME function bodies except the `buildNSAnswerChunks` core extraction and comment lines named in the tasks.
- No new exported symbols in `enums`, `vpnproto`, `basecodec`.
- Use stdlib `math/rand` for ROTATE (auto-seeded).
- Commit style: `feat: ...` / `test: ...` / `docs: ...` short lowercase summaries (repo convention).
- Run `gofmt -l .` (no output for touched files), `go vet ./...`, `go build ./cmd/client && go build ./cmd/server`, `go test -timeout 300s ./...` before the final commit.

---

### Task 1: Parser decodes SRV target names (`RDataName`)

**Files:**
- Modify: `internal/dnsparser/parser.go` (struct comment ~line 60; `parseResourceRecords` name-decode block ~lines 250-260; add helper next to `isNameRDataRecordType`)
- Test: `internal/dnsparser/srv_test.go` (new)

**Interfaces:**
- Consumes: existing `parseName(data []byte, offset int) (string, int, error)`.
- Produces:
  - `func nameRDataNameOffset(recordType uint16) int` — 0 for NS/CNAME, 6 for SRV, −1 otherwise.
  - `ResourceRecord.RDataName` populated for SRV target names; `""` when n/a, root, or undecodable.
  - `isNameRDataRecordType` stays defined in this task (still used by `transport.go` until Task 2).

- [x] **Step 1: Write the failing tests**

Create `internal/dnsparser/srv_test.go` (package `dnsparser`):

```go
// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"bytes"
	"encoding/binary"
	"testing"

	Enums "stormdns-go/internal/enums"
)

// buildSRVAnswerTestPacket crafts a single-question, single-answer response
// whose answer type is SRV and whose rdata is exactly the bytes given. The
// owner is written as a compression pointer to the question name (0xC00C).
func buildSRVAnswerTestPacket(t *testing.T, rdata []byte) []byte {
	t.Helper()
	question, err := BuildTXTQuestionPacket("x.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 0, len(question)+2+10+len(rdata))
	packet = append(packet, question...)
	binary.BigEndian.PutUint16(packet[6:8], 1) // ANCount = 1
	packet = append(packet, 0xC0, 0x0C)        // owner: pointer to qname
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_SRV)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	packet = append(packet, fixed[:]...)
	packet = append(packet, rdata...)
	return packet
}

// srvRData prepends the six-byte priority/weight/port prefix to a target name.
func srvRData(targetWire []byte) []byte {
	rdata := make([]byte, 0, 6+len(targetWire))
	rdata = append(rdata, 0, 0, 0, 0, 0, 0)
	return append(rdata, targetWire...)
}

func TestParsePacketDecodesSRVTargetNamePlain(t *testing.T) {
	target, err := encodeDNSNameStrict("srv1.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, srvRData(target)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "srv1.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "srv1.v.example.com")
	}
	if len(parsed.Answers[0].RData) != 6+len(target) {
		t.Fatalf("RData len = %d, want %d", len(parsed.Answers[0].RData), 6+len(target))
	}
}

func TestParsePacketDecodesSRVTargetAfterFixedFields(t *testing.T) {
	// The fixed fields spell a decodable name ("fak") if the parser wrongly
	// starts at rdata offset 0; the real target only appears at offset 6.
	target, err := encodeDNSNameStrict("real.v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	rdata := append([]byte{3, 'f', 'a', 'k', 0, 0}, target...)
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, rdata))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "real.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "real.v.example.com")
	}
}

func TestParsePacketDecodesSRVTargetCompressed(t *testing.T) {
	// rdata target is a compression pointer to the question name (0xC00C).
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{0, 0, 0, 0, 0, 0, 0xC0, 0x0C}))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if got := parsed.Answers[0].RDataName; got != "x.v.example.com" {
		t.Fatalf("RDataName = %q, want %q", got, "x.v.example.com")
	}
}

func TestParsePacketDecodesSRVRootTarget(t *testing.T) {
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{1, 2, 3, 4, 5, 6, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].RDataName != "" {
		t.Fatalf("root target must decode to empty RDataName, got %q", parsed.Answers[0].RDataName)
	}
	if !bytes.Equal(parsed.Answers[0].RData, []byte{1, 2, 3, 4, 5, 6, 0}) {
		t.Fatalf("RData = %v, want fixed bytes + root", parsed.Answers[0].RData)
	}
}

func TestParsePacketToleratesShortSRVRData(t *testing.T) {
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{1, 2, 3}))
	if err != nil {
		t.Fatalf("parse must not fail on short SRV rdata: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}

func TestParsePacketToleratesGarbageSRVTarget(t *testing.T) {
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{0, 0, 0, 0, 0, 0, 63, 'a', 'b'}))
	if err != nil {
		t.Fatalf("parse must not fail on malformed SRV target: %v", err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].RDataName != "" {
		t.Fatalf("want 1 answer with empty RDataName, got %+v", parsed.Answers)
	}
}
```

Note: Task 2 appends tests to this same file and extends the import block with `"errors"` and `VpnProto "stormdns-go/internal/vpnproto"` in the same step.

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dnsparser/ -run 'TestParsePacketDecodesSRV|TestParsePacketToleratesShortSRV|TestParsePacketToleratesGarbageSRV' -v`
Expected: FAIL — `TestParsePacketDecodesSRVTargetNamePlain` and `TestParsePacketDecodesSRVTargetAfterFixedFields` report empty `RDataName`; compressed and root/garbage/short cases may already pass (they assert empty/absence behavior).

- [x] **Step 3: Implement**

In `internal/dnsparser/parser.go`:

1. Update the `ResourceRecord.RDataName` field comment:
```go
	RDataName string // decoded rdata name for name-type records (NS/CNAME at offset 0, SRV target at offset 6); "" when n/a, root, or undecodable
```
2. Add this helper immediately above `isNameRDataRecordType`:
```go
// nameRDataNameOffset returns the offset of the domain name inside the rdata
// for record types whose rdata carries a name: NS and CNAME start at offset 0;
// SRV starts after the 6-byte priority/weight/port prefix. Returns -1 when the
// rdata holds no name.
func nameRDataNameOffset(recordType uint16) int {
	switch recordType {
	case Enums.DNS_RECORD_TYPE_NS, Enums.DNS_RECORD_TYPE_CNAME:
		return 0
	case Enums.DNS_RECORD_TYPE_SRV:
		return 6
	default:
		return -1
	}
}
```
3. Replace the NS/CNAME decode block inside `parseResourceRecords`:
```go
		// NS/CNAME rdata is a domain name starting at offset 0; SRV rdata
		// carries its target name after the 6-byte priority/weight/port
		// prefix. Decode it so tunnel payloads carried in those names can be
		// read. A decode failure (or a name that overruns rdLen) leaves
		// RDataName empty and never fails the whole packet parse.
		if nameOffset := nameRDataNameOffset(rType); nameOffset >= 0 && offset+nameOffset < end {
			if nameText, nameNext, nameErr := parseName(data, offset+nameOffset); nameErr == nil && nameNext <= end {
				records[i].RDataName = nameText
			}
		}
```
Do **not** delete `isNameRDataRecordType` yet — `transport.go` still calls it until Task 2.

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestParsePacketDecodesSRV|TestParsePacketToleratesShortSRV|TestParsePacketToleratesGarbageSRV' -v`
Expected: PASS (all 6).

Then package regression:
Run: `go test ./internal/dnsparser/`
Expected: PASS (NS/CNAME/TXT parser tests unchanged).

- [x] **Step 5: Commit**

```bash
git add internal/dnsparser/parser.go internal/dnsparser/srv_test.go
git commit -m "feat: decode SRV target names in DNS parser"
```

---

### Task 2: SRV tunnel answers and client extraction

**Files:**
- Modify: `internal/dnsparser/transport.go` (`maxNSUnitBytes` comment ~line 371; `buildNSAnswerChunks` ~lines 380-441; `questionTypeIsCNAME`/`buildCNAMEVPNResponse` area ~lines 444-490; `buildSingleCNAMEResponsePacket`/`BuildNSResponsePacket` area ~lines 492-644; `BuildVPNResponsePacket` dispatch ~lines 296-305; `decodeNSAnswerName`/`extractAnswerUnits` ~lines 700-750)
- Modify: `internal/dnsparser/parser.go` (delete now-unused `isNameRDataRecordType` after transport use is replaced)
- Test: `internal/dnsparser/srv_test.go` (append)

**Interfaces:**
- Consumes: Task 1 `nameRDataNameOffset` (parser populates SRV `RDataName`), existing `buildNSAnswerName`, `decodeNSAnswerName`, `responseAnswerNameBytes`, `buildResponseFlags`, `extractQuestionSection`, `findOPTRecordRange`, `parseHeader`, `ParsePacketLite`, `getARCount`, `dnsHeaderSize`, `VpnProto.BuildRawAuto`, `VpnProto.Parse`.
- Produces (all in `transport.go`):
  - `func maxSRVUnitBytes() int` — `maxNSUnitBytes() + 6` = 165
  - `func buildNameAnswerUnits(rawFrame []byte, maxUnit int, minUnit int) ([][]byte, error)` — shared chunker; units ≥ `minUnit` (when `minUnit > 1`)
  - `func buildSRVAnswerRData(unit []byte) ([]byte, error)` — 6 fixed bytes + base36 target name; root target for a 6-byte unit
  - `func buildSRVAnswerChunks(rawFrame []byte) ([][]byte, error)` — one rdata blob per unit
  - `func questionTypeIsSRV(questionPacket []byte) bool`
  - `func buildSRVVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error)`
  - `func buildSingleSRVResponsePacket(questionPacket []byte, answerName string, answerRData []byte) ([]byte, error)`
  - `func BuildSRVResponsePacket(questionPacket []byte, answerName string, answerRDatas [][]byte) ([]byte, error)`
  - `func decodeNameRDataUnit(answer ResourceRecord) ([]byte, bool)` — per-type unit decode incl. SRV fixed bytes + root target
  - `BuildVPNResponsePacket` dispatches SRV after CNAME; `extractAnswerUnits` uses `decodeNameRDataUnit`; `buildNSAnswerChunks` delegates to `buildNameAnswerUnits` (byte-identical behavior)

- [x] **Step 1: Write the failing tests**

Append to `internal/dnsparser/srv_test.go` and extend its imports with `"errors"` and `VpnProto "stormdns-go/internal/vpnproto"` (final import block):

```go
import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)
```

```go
// ---- Task 2: SRV transport builders and extraction ----

func TestSRVUnitCapacityIsNSCapacityPlusSix(t *testing.T) {
	if got := maxNSUnitBytes(); got != 159 {
		t.Fatalf("maxNSUnitBytes() = %d, want 159 (base36 250-char budget)", got)
	}
	if got, want := maxSRVUnitBytes(), maxNSUnitBytes()+6; got != want {
		t.Fatalf("maxSRVUnitBytes() = %d, want %d", got, want)
	}
}

func TestBuildSRVAnswerRDataCarriesFixedBytesAndTarget(t *testing.T) {
	unit := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x10, 0x20, 0x30}
	rdata, err := buildSRVAnswerRData(unit)
	if err != nil {
		t.Fatal(err)
	}
	if len(rdata) < 6 || !bytes.Equal(rdata[:6], unit[:6]) {
		t.Fatalf("fixed fields = %v, want %v", rdata[:6], unit[:6])
	}
	nameText, _, err := parseName(rdata, 6)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeNSAnswerName(nameText)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, unit[6:]) {
		t.Fatalf("target carries %v, want %v", decoded, unit[6:])
	}
}

func TestBuildSRVAnswerRDataEncodesSixByteUnitAsRootTarget(t *testing.T) {
	unit := []byte{1, 2, 3, 4, 5, 6}
	rdata, err := buildSRVAnswerRData(unit)
	if err != nil {
		t.Fatal(err)
	}
	if len(rdata) != 7 || rdata[6] != 0 {
		t.Fatalf("six-byte unit must encode as fixed bytes + root target, got %v", rdata)
	}
	if !bytes.Equal(rdata[:6], unit) {
		t.Fatalf("fixed fields = %v, want %v", rdata[:6], unit)
	}
}

func TestDecodeNameRDataUnitReadsSRVFixedBytes(t *testing.T) {
	targetWire, err := buildNSAnswerName([]byte{0xAA, 0xBB})
	if err != nil {
		t.Fatal(err)
	}
	rdata := append([]byte{1, 2, 3, 4, 5, 6}, targetWire...)
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, rdata))
	if err != nil {
		t.Fatal(err)
	}
	unit, ok := decodeNameRDataUnit(parsed.Answers[0])
	if !ok {
		t.Fatal("SRV answer did not decode to a unit")
	}
	if !bytes.Equal(unit, []byte{1, 2, 3, 4, 5, 6, 0xAA, 0xBB}) {
		t.Fatalf("unit = %v, want fixed bytes + decoded target", unit)
	}
}

func TestDecodeNameRDataUnitReadsSRVRootTarget(t *testing.T) {
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{1, 2, 3, 4, 5, 6, 0}))
	if err != nil {
		t.Fatal(err)
	}
	unit, ok := decodeNameRDataUnit(parsed.Answers[0])
	if !ok {
		t.Fatal("root-target SRV answer did not decode to a unit")
	}
	if !bytes.Equal(unit, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("unit = %v, want the six fixed bytes", unit)
	}
}

func TestDecodeNameRDataUnitSkipsMalformedSRV(t *testing.T) {
	parsed, err := ParsePacket(buildSRVAnswerTestPacket(t, []byte{1, 2, 3, 4, 5, 6, 63, 'a', 'b'}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeNameRDataUnit(parsed.Answers[0]); ok {
		t.Fatal("malformed SRV rdata must not decode to a unit")
	}
}

func TestBuildVPNResponsePacketMirrorsSRVQuestionSingle(t *testing.T) {
	question, err := BuildTXTQuestionPacket("a1b2.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello srv world")
	resp, err := BuildVPNResponsePacket(question, "a1b2.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Type != Enums.DNS_RECORD_TYPE_SRV {
		t.Fatalf("question type not echoed: %+v", parsed.Questions)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("want 1 SRV answer, got %d", len(parsed.Answers))
	}
	if parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_SRV {
		t.Fatalf("answer type = %d, want SRV(%d)", parsed.Answers[0].Type, Enums.DNS_RECORD_TYPE_SRV)
	}
	if len(parsed.Answers[0].RData) < 7 {
		t.Fatalf("SRV rdata too short: %v", parsed.Answers[0].RData)
	}
	for _, label := range splitLabels(parsed.Answers[0].RDataName) {
		if len(label) > 63 {
			t.Fatalf("label %q exceeds 63 chars", label)
		}
	}

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%q", got.PacketType, got.Payload)
	}
}

func TestBuildVPNResponsePacketMirrorsSRVQuestionMulti(t *testing.T) {
	question, err := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := patternedPayload(800) // forces multiple SRV answer records
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", VpnProto.Packet{
		SessionID:      7,
		PacketType:     Enums.PACKET_STREAM_DATA, // carries stream/seq in the header
		StreamID:       3,
		SequenceNum:    99,
		TotalFragments: 1,
		Payload:        payload,
	}, true /* base64 flag must be irrelevant for SRV */)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("want multiple SRV answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_SRV {
			t.Fatalf("answer %d type = %d, want SRV", i, ans.Type)
		}
		if ans.Name != "aa.bb.v.example.com" {
			t.Fatalf("answer %d owner = %q, want qname", i, ans.Name)
		}
		unit, ok := decodeNameRDataUnit(ans)
		if !ok || len(unit) < 6 {
			t.Fatalf("answer %d did not decode to a >= 6-byte unit (ok=%v len=%d)", i, ok, len(unit))
		}
	}

	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_STREAM_DATA || got.StreamID != 3 || got.SequenceNum != 99 ||
		!bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d stream=%d seq=%d payloadlen=%d",
			got.PacketType, got.StreamID, got.SequenceNum, len(got.Payload))
	}
}

func TestSRVAnswerRoundTripAcrossChunkBoundaries(t *testing.T) {
	question, err := BuildTXTQuestionPacket("barrage.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	for size := 0; size <= 600; size++ {
		payload := patternedPayload(size)
		resp, err := BuildVPNResponsePacket(question, "barrage.v.example.com", VpnProto.Packet{
			SessionID:      7,
			PacketType:     Enums.PACKET_STREAM_DATA,
			StreamID:       3,
			SequenceNum:    1,
			TotalFragments: 1,
			Payload:        payload,
		}, false)
		if err != nil {
			t.Fatalf("size %d: build failed: %v", size, err)
		}
		parsed, err := ParsePacket(resp)
		if err != nil {
			t.Fatalf("size %d: parse failed: %v", size, err)
		}
		for i, ans := range parsed.Answers {
			unit, ok := decodeNameRDataUnit(ans)
			if !ok {
				t.Fatalf("size %d: answer %d undecodable", size, i)
			}
			if len(unit) < 6 {
				t.Fatalf("size %d: answer %d unit len %d < 6", size, i, len(unit))
			}
		}
		got, err := ExtractVPNResponse(resp, false)
		if err != nil {
			t.Fatalf("size %d: extract failed: %v", size, err)
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Fatalf("size %d: payload mismatch (got %d bytes)", size, len(got.Payload))
		}
	}
}

func TestExtractVPNResponseReadsSRVWithBase64Flag(t *testing.T) {
	question, err := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := VpnProto.BuildRaw(VpnProto.BuildOptions{
		SessionID:  7,
		PacketType: Enums.PACKET_PONG,
		Payload:    []byte{1, 2, 3, 4, 5},
	})
	if err != nil {
		t.Fatal(err)
	}
	rdata, err := buildSRVAnswerRData(frame)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := buildSingleSRVResponsePacket(question, "k9.v.example.com", rdata)
	if err != nil {
		t.Fatal(err)
	}

	// baseEncoded=true must not corrupt SRV-unit decoding (the fixed bytes are
	// raw and the name transport is charset-safe by itself).
	got, err := ExtractVPNResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("roundtrip mismatch: type=%d payload=%v", got.PacketType, got.Payload)
	}
}

func TestBuildSRVVPNResponseShortFrameFallsBackToNS(t *testing.T) {
	question, err := BuildTXTQuestionPacket("k9.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := buildSRVVPNResponse(question, "k9.v.example.com", []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) != 1 || parsed.Answers[0].Type != Enums.DNS_RECORD_TYPE_NS {
		t.Fatalf("short SRV frame must fall back to an NS answer, got %+v", parsed.Answers)
	}
}

func TestExtractVPNResponseNoPayloadFromUnreadableSRV(t *testing.T) {
	// An SRV answer whose rdata cannot be decoded must behave like a response
	// without tunnel payload: ErrTXTAnswerMissing, not a panic.
	resp := buildSRVAnswerTestPacket(t, []byte{0, 0, 0, 0, 0, 0, 63, 'a', 'b'})
	if _, err := ExtractVPNResponse(resp, false); !errors.Is(err, ErrTXTAnswerMissing) {
		t.Fatalf("want ErrTXTAnswerMissing, got %v", err)
	}
}

func TestExtractVPNResponseIgnoresRecordsAppendedToSRV(t *testing.T) {
	// Recursors may append address records after the SRV RRset; units must come
	// only from the SRV rdata, in order.
	payload := patternedPayload(400)
	question, err := BuildTXTQuestionPacket("aa.bb.v.example.com", Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildVPNResponsePacket(question, "aa.bb.v.example.com", vpnPacketForTest(payload), false)
	if err != nil {
		t.Fatal(err)
	}

	owner, err := encodeDNSNameStrict("extra.example.net")
	if err != nil {
		t.Fatal(err)
	}
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], Enums.DNS_RECORD_TYPE_A)
	binary.BigEndian.PutUint16(fixed[2:4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint16(fixed[8:10], 4)
	resp = append(resp, owner...)
	resp = append(resp, fixed[:]...)
	resp = append(resp, 1, 2, 3, 4)
	anCount := binary.BigEndian.Uint16(resp[6:8])
	binary.BigEndian.PutUint16(resp[6:8], anCount+1)

	got, err := ExtractVPNResponse(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.PacketType != Enums.PACKET_PONG || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("roundtrip mismatch: type=%d payloadlen=%d", got.PacketType, len(got.Payload))
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dnsparser/ -run 'TestSRVUnitCapacity|TestBuildSRV|TestDecodeNameRDataUnit|TestBuildVPNResponsePacketMirrorsSRV|TestSRVAnswerRoundTrip|TestExtractVPNResponseReadsSRV|TestExtractVPNResponseNoPayloadFromUnreadableSRV|TestExtractVPNResponseIgnoresRecordsAppendedToSRV|TestBuildSRVVPNResponseShortFrame' -v`
Expected: FAIL to compile — `undefined: maxSRVUnitBytes`, `undefined: buildSRVAnswerRData`, `undefined: decodeNameRDataUnit`, `undefined: buildSingleSRVResponsePacket`, `undefined: buildSRVVPNResponse`.

- [x] **Step 3: Implement**

In `internal/dnsparser/transport.go`:

1. Update the `maxNSUnitBytes` comment (replace "~161 bytes" wording):
```go
// maxNSUnitBytes returns the largest raw chunk size whose base36 text fits in
// maxNSNameChars (159 bytes: EncodedLenLowerBase36(159) = 250). Shared by the
// NS and CNAME name transports.
```
2. Add `maxSRVUnitBytes` immediately after `maxNSUnitBytes`:
```go
// maxSRVUnitBytes returns the largest SRV payload unit: the 6-byte
// priority/weight/port prefix plus the base36 target-name budget shared with
// the NS/CNAME name transport.
func maxSRVUnitBytes() int {
	return maxNSUnitBytes() + 6
}
```
3. Replace `buildNSAnswerChunks` with the shared chunker plus wrapper:
```go
// buildNameAnswerUnits splits rawFrame into chunk units with the same byte
// layout as the TXT chunker (chunk 0: [0x00][total][vpn header][payload...],
// chunk N: [id][payload...]). maxUnit is the largest unit the transport can
// carry; minUnit is the smallest unit its decoder can represent (0 = no floor).
// When the natural split would leave the final chunk below minUnit, bytes move
// up from the previous chunk (always full when a later chunk exists) so byte
// order and the chunk count are preserved.
func buildNameAnswerUnits(rawFrame []byte, maxUnit int, minUnit int) ([][]byte, error) {
	header, err := VpnProto.Parse(rawFrame)
	if err != nil {
		return nil, err
	}

	headerLen := header.HeaderLength
	maxChunk0Data := max(maxUnit-2-headerLen, 0)
	remaining := len(header.Payload) - maxChunk0Data
	maxChunkNData := maxUnit - 1
	totalChunks := 1
	if remaining > 0 {
		totalChunks += (remaining + maxChunkNData - 1) / maxChunkNData
	}
	if totalChunks > 255 {
		return nil, ErrTXTAnswerTooLarge
	}

	chunkDataLens := make([]int, totalChunks)
	chunkDataLens[0] = min(maxChunk0Data, len(header.Payload))
	cursor := chunkDataLens[0]
	for i := 1; i < totalChunks; i++ {
		end := min(cursor+maxChunkNData, len(header.Payload))
		chunkDataLens[i] = end - cursor
		cursor = end
	}
	if minUnit > 1 && totalChunks > 1 {
		last := totalChunks - 1
		if deficit := minUnit - (1 + chunkDataLens[last]); deficit > 0 {
			chunkDataLens[last-1] -= deficit
			chunkDataLens[last] += deficit
		}
	}

	units := make([][]byte, 0, totalChunks)
	rawChunk0 := make([]byte, 2+headerLen+chunkDataLens[0])
	rawChunk0[0] = 0x00
	rawChunk0[1] = byte(totalChunks)
	copy(rawChunk0[2:], rawFrame[:headerLen])
	copy(rawChunk0[2+headerLen:], header.Payload[:chunkDataLens[0]])
	units = append(units, rawChunk0)

	cursor = chunkDataLens[0]
	for chunkID := 1; chunkID < totalChunks; chunkID++ {
		dataLen := chunkDataLens[chunkID]
		rawChunk := make([]byte, 1+dataLen)
		rawChunk[0] = byte(chunkID)
		copy(rawChunk[1:], header.Payload[cursor:cursor+dataLen])
		units = append(units, rawChunk)
		cursor += dataLen
	}
	return units, nil
}

// buildNSAnswerChunks splits rawFrame into chunk units (see
// buildNameAnswerUnits) and returns one rdata wire name per unit (shared by
// the NS and CNAME name transports).
func buildNSAnswerChunks(rawFrame []byte) ([][]byte, error) {
	if len(rawFrame) == 0 {
		return [][]byte{{0}}, nil // root-name placeholder; real frames are never empty
	}

	units, err := buildNameAnswerUnits(rawFrame, maxNSUnitBytes(), 0)
	if err != nil {
		return nil, err
	}
	names := make([][]byte, len(units))
	for i, unit := range units {
		name, err := buildNSAnswerName(unit)
		if err != nil {
			return nil, err
		}
		names[i] = name
	}
	return names, nil
}

// buildSRVAnswerRData packs one transport unit into SRV rdata: the first six
// unit bytes become the priority/weight/port fields (big-endian), the rest
// becomes the base36 target name. A six-byte unit gets a root target, which
// decodes back to exactly those six bytes.
func buildSRVAnswerRData(unit []byte) ([]byte, error) {
	if len(unit) < 6 {
		return nil, ErrTXTAnswerMalformed
	}
	nameWire, err := buildNSAnswerName(unit[6:])
	if err != nil {
		return nil, err
	}
	rdata := make([]byte, 0, 6+len(nameWire))
	rdata = append(rdata, unit[:6]...)
	rdata = append(rdata, nameWire...)
	return rdata, nil
}

// buildSRVAnswerChunks splits rawFrame into units of at most maxSRVUnitBytes,
// each at least six bytes, and returns one SRV rdata blob per unit.
func buildSRVAnswerChunks(rawFrame []byte) ([][]byte, error) {
	if len(rawFrame) == 0 {
		return [][]byte{{0, 0, 0, 0, 0, 0, 0}}, nil // fixed bytes + root target
	}

	units, err := buildNameAnswerUnits(rawFrame, maxSRVUnitBytes(), 6)
	if err != nil {
		return nil, err
	}
	rdatas := make([][]byte, len(units))
	for i, unit := range units {
		rdata, err := buildSRVAnswerRData(unit)
		if err != nil {
			return nil, err
		}
		rdatas[i] = rdata
	}
	return rdatas, nil
}
```
4. Add `questionTypeIsSRV` after `questionTypeIsCNAME`:
```go
// questionTypeIsSRV reports whether the packet's first question asks for SRV.
func questionTypeIsSRV(questionPacket []byte) bool {
	lite, err := ParsePacketLite(questionPacket)
	return err == nil && lite.HasQuestion && lite.FirstQuestion.Type == Enums.DNS_RECORD_TYPE_SRV
}
```
5. Add `buildSRVVPNResponse` after `buildCNAMEVPNResponse`:
```go
// buildSRVVPNResponse builds a single-answer or multi-answer SRV response whose
// rdata carries rawFrame (single) or its chunk units (multi). Frames shorter
// than six bytes cannot use the six fixed rdata bytes without ambiguity, so
// the degenerate case is answered NS-style; the client extractor is
// per-answer-type and reads it either way.
func buildSRVVPNResponse(questionPacket []byte, answerName string, rawFrame []byte) ([]byte, error) {
	if len(rawFrame) < 6 {
		return buildNSVPNResponse(questionPacket, answerName, rawFrame)
	}
	if len(rawFrame) <= maxSRVUnitBytes() {
		rdata, err := buildSRVAnswerRData(rawFrame)
		if err != nil {
			return nil, err
		}
		return buildSingleSRVResponsePacket(questionPacket, answerName, rdata)
	}

	rdatas, err := buildSRVAnswerChunks(rawFrame)
	if err != nil {
		return nil, err
	}
	return BuildSRVResponsePacket(questionPacket, answerName, rdatas)
}
```
6. In `BuildVPNResponsePacket`, add the SRV branch after the CNAME branch:
```go
	if questionTypeIsNS(questionPacket) {
		return buildNSVPNResponse(questionPacket, answerName, rawFrame)
	}
	if questionTypeIsCNAME(questionPacket) {
		return buildCNAMEVPNResponse(questionPacket, answerName, rawFrame)
	}
	if questionTypeIsSRV(questionPacket) {
		return buildSRVVPNResponse(questionPacket, answerName, rawFrame)
	}
```
7. Add `buildSingleSRVResponsePacket` after `buildSingleCNAMEResponsePacket`:
```go
func buildSingleSRVResponsePacket(questionPacket []byte, answerName string, answerRData []byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+len(nameBytes)+10+len(answerRData)+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	offset += copy(response[offset:], nameBytes)
	binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_SRV)
	binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
	binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
	binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerRData)))
	offset += 10
	offset += copy(response[offset:], answerRData)

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}
```
8. Add `BuildSRVResponsePacket` after `BuildNSResponsePacket`:
```go
// BuildSRVResponsePacket builds a multi-answer SRV response: one record per
// unit, every record owning the query name (first full name, later 2-byte
// compression pointers). SRV RRsets legally repeat an owner name, so this
// mirrors BuildNSResponsePacket instead of the CNAME chain shape.
func BuildSRVResponsePacket(questionPacket []byte, answerName string, answerRDatas [][]byte) ([]byte, error) {
	if len(questionPacket) < dnsHeaderSize {
		return nil, ErrPacketTooShort
	}

	header := parseHeader(questionPacket)
	questionBytes, questionCount, questionEndOffset := extractQuestionSection(questionPacket, header)
	optStart, optLen := findOPTRecordRange(questionPacket, header, questionEndOffset)

	nameBytes, err := responseAnswerNameBytes(questionPacket, answerName)
	if err != nil {
		return nil, err
	}

	answerLen := 0
	useAnswerNameCompression := len(answerRDatas) > 1
	for i, answerRData := range answerRDatas {
		nameLen := len(nameBytes)
		if useAnswerNameCompression && i > 0 {
			nameLen = 2
		}
		answerLen += nameLen + 10 + len(answerRData)
	}

	response := make([]byte, dnsHeaderSize+len(questionBytes)+answerLen+optLen)
	binary.BigEndian.PutUint16(response[0:2], header.ID)
	binary.BigEndian.PutUint16(response[2:4], buildResponseFlags(header.Flags, Enums.DNSR_CODE_NO_ERROR))
	binary.BigEndian.PutUint16(response[4:6], questionCount)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answerRDatas)))
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], uint16(getARCount(optLen)))

	offset := dnsHeaderSize
	offset += copy(response[offset:], questionBytes)
	firstAnswerNameOffset := offset

	for i, answerRData := range answerRDatas {
		if useAnswerNameCompression && i > 0 && firstAnswerNameOffset <= 0x3FFF {
			binary.BigEndian.PutUint16(response[offset:offset+2], uint16(0xC000|firstAnswerNameOffset))
			offset += 2
		} else {
			offset += copy(response[offset:], nameBytes)
		}
		binary.BigEndian.PutUint16(response[offset:offset+2], Enums.DNS_RECORD_TYPE_SRV)
		binary.BigEndian.PutUint16(response[offset+2:offset+4], Enums.DNSQ_CLASS_IN)
		binary.BigEndian.PutUint32(response[offset+4:offset+8], 0)
		binary.BigEndian.PutUint16(response[offset+8:offset+10], uint16(len(answerRData)))
		offset += 10
		offset += copy(response[offset:], answerRData)
	}

	if optLen > 0 {
		copy(response[offset:], questionPacket[optStart:optStart+optLen])
	}

	return response, nil
}
```
9. Update the `decodeNSAnswerName` comment:
```go
// decodeNSAnswerName decodes a name-rdata target (NS, CNAME, or the SRV
// target) back into the payload unit bytes: label text (dots removed) is
// lowercase-base36.
```
10. Add `decodeNameRDataUnit` immediately above `extractAnswerUnits`, and replace the name-unit loop in `extractAnswerUnits`:
```go
// decodeNameRDataUnit decodes one name-transport answer record back into its
// payload unit. NS and CNAME carry the whole unit in the rdata name. SRV
// carries the first six unit bytes in the priority/weight/port fields and the
// rest in the target name; a root target is the exact encoding of a six-byte
// unit. Malformed records return ok=false and are skipped.
func decodeNameRDataUnit(answer ResourceRecord) ([]byte, bool) {
	switch answer.Type {
	case Enums.DNS_RECORD_TYPE_NS, Enums.DNS_RECORD_TYPE_CNAME:
		if answer.RDataName == "" {
			return nil, false
		}
		decoded, err := decodeNSAnswerName(answer.RDataName)
		if err != nil || len(decoded) == 0 {
			return nil, false
		}
		return decoded, true
	case Enums.DNS_RECORD_TYPE_SRV:
		if len(answer.RData) < 6 {
			return nil, false
		}
		if answer.RDataName == "" {
			// Root target: the whole unit fit in the six fixed bytes.
			if len(answer.RData) != 7 || answer.RData[6] != 0 {
				return nil, false
			}
			return append([]byte(nil), answer.RData[:6]...), true
		}
		decoded, err := decodeNSAnswerName(answer.RDataName)
		if err != nil {
			return nil, false
		}
		unit := make([]byte, 0, 6+len(decoded))
		unit = append(unit, answer.RData[:6]...)
		unit = append(unit, decoded...)
		return unit, true
	default:
		return nil, false
	}
}
```
Replace this block in `extractAnswerUnits`:
```go
	nameUnits := make([][]byte, 0, len(parsed.Answers))
	for _, answer := range parsed.Answers {
		unit, ok := decodeNameRDataUnit(answer)
		if !ok {
			continue
		}
		nameUnits = append(nameUnits, unit)
	}
```
and update the `extractAnswerUnits` doc comment to say "NS, CNAME, or SRV" instead of "NS or CNAME".

11. In `internal/dnsparser/parser.go`, delete the now-unused `isNameRDataRecordType` function (verify with `rg -n "isNameRDataRecordType" internal/` — expected: no matches).

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsparser/ -run 'TestSRVUnitCapacity|TestBuildSRV|TestDecodeNameRDataUnit|TestBuildVPNResponsePacketMirrorsSRV|TestSRVAnswerRoundTrip|TestExtractVPNResponseReadsSRV|TestExtractVPNResponseNoPayloadFromUnreadableSRV|TestExtractVPNResponseIgnoresRecordsAppendedToSRV|TestBuildSRVVPNResponseShortFrame' -v`
Expected: PASS (all 13).

Then full package regression (NS/CNAME/TXT):
Run: `go test ./internal/dnsparser/`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/dnsparser/transport.go internal/dnsparser/parser.go internal/dnsparser/srv_test.go
git commit -m "feat: SRV tunnel answers (fixed-byte payload channel + name extraction)"
```

---

### Task 3: Matcher accepts SRV tunnel queries

**Files:**
- Modify: `internal/domainmatcher/matcher.go` (qtype gate ~lines 92-94)
- Test: `internal/domainmatcher/matcher_test.go` (append)

**Interfaces:**
- Consumes: existing `litePacketWithQuestion` test helper.
- Produces: `Matcher.Match` returns `ActionProcess` for SRV questions with valid labels; other qtypes keep `Reason: "unsupported-qtype"`. `internal/dnsparser/policy.go` already accepts SRV — no change.

- [x] **Step 1: Write the failing test**

Append to `internal/domainmatcher/matcher_test.go`:

```go
func TestMatcherReturnsProcessForSRVQuestion(t *testing.T) {
	matcher := New([]string{"a.com", "c.b.com", "cc.com"}, 3)

	decision := matcher.Match(litePacketWithQuestion("vpn-01.c.b.com", Enums.DNS_RECORD_TYPE_SRV))
	if decision.Action != ActionProcess {
		t.Fatalf("unexpected action: got=%d want=%d", decision.Action, ActionProcess)
	}
	if decision.QuestionType != Enums.DNS_RECORD_TYPE_SRV {
		t.Fatalf("unexpected question type: got=%d want=%d", decision.QuestionType, Enums.DNS_RECORD_TYPE_SRV)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domainmatcher/ -run TestMatcherReturnsProcessForSRVQuestion -v`
Expected: FAIL — action `ActionNoData`, reason `unsupported-qtype`.

- [x] **Step 3: Implement**

In `internal/domainmatcher/matcher.go`, extend the qtype gate:
```go
	if q0.Type != Enums.DNS_RECORD_TYPE_TXT && q0.Type != Enums.DNS_RECORD_TYPE_NS &&
		q0.Type != Enums.DNS_RECORD_TYPE_CNAME && q0.Type != Enums.DNS_RECORD_TYPE_SRV {
		return Decision{
			Action:       ActionNoData,
			Reason:       "unsupported-qtype",
			Question:     q0,
			RequestName:  requestName,
			BaseDomain:   baseDomain,
			QuestionType: q0.Type,
		}
	}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/domainmatcher/ -v`
Expected: PASS (new + all existing).

- [x] **Step 5: Commit**

```bash
git add internal/domainmatcher/matcher.go internal/domainmatcher/matcher_test.go
git commit -m "feat: accept SRV qtype as tunnel query"
```

---

### Task 4: Client config `DNS_QUERY_TYPE` accepts SRV + docs

**Files:**
- Modify: `internal/config/client.go` (validation switch ~line 361)
- Modify: `internal/config/client_test.go` (append)
- Modify: `client_config.toml.simple` (comment block lines 205-210)
- Modify: `README.MD` (paragraph line 190, table lines 194-199, note line 201, FAQ line 683)

**Interfaces:**
- Produces: `DNS_QUERY_TYPE` accepts `"TXT"` (default), `"NS"`, `"CNAME"`, `"SRV"`, `"ROTATE"`; anything else → error `invalid DNS_QUERY_TYPE: %q`.

- [x] **Step 1: Write the failing test**

Append to `internal/config/client_test.go` (uses the existing `writeClientConfigForTest` helper):

```go
func TestClientConfigDNSQueryTypeNormalizesSRV(t *testing.T) {
	cfg := writeClientConfigForTest(t, `
DNS_QUERY_TYPE = "srv"
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = "secret"
DOMAINS = ["v.domain.com"]
`)
	if cfg.DNSQueryType != "SRV" {
		t.Fatalf("DNSQueryType = %q, want %q", cfg.DNSQueryType, "SRV")
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestClientConfigDNSQueryTypeNormalizesSRV -v`
Expected: FAIL — `invalid DNS_QUERY_TYPE: "SRV"`.

- [x] **Step 3: Implement**

1. In `internal/config/client.go`, extend the validation switch:
```go
	case "NS", "CNAME", "SRV", "ROTATE":
```
2. In `client_config.toml.simple`, replace the comment block above `DNS_QUERY_TYPE = "TXT"` (lines 205-210) with:
```toml
# DNS record type used for tunnel queries.
#   "TXT"    - default, works with every server version
#   "NS"     - tunnel over NS queries/answers; use when the resolver path blocks TXT
#   "CNAME"  - tunnel over CNAME query/answer chains; the most web-like query shape
#   "SRV"    - tunnel over SRV queries/answers; use when the other types are filtered
#   "ROTATE" - random TXT/NS/CNAME/SRV mix per query (disguise); requires a matching server
DNS_QUERY_TYPE = "TXT"
```
3. In `README.MD`:
   - Replace the delegation paragraph at line 190:
```markdown
**These same two records serve every tunnel query type — TXT, NS, CNAME, SRV, or a ROTATE mix. No extra DNS records are needed.** Delegation is type-agnostic: queries of any type for `v.example.com` or for names beneath it (payload-carrying tunnel names are always subdomains of the tunnel domain) are referred to `ns.example.com` and reach your server. The server answers each query with the same record type it was asked for (TXT questions get TXT answers, NS questions get NS answers, CNAME questions get CNAME answer chains, SRV questions get SRV answers, all with TTL 0), so resolvers never cache tunnel traffic.
```
   - Add the SRV row to the table after the `"CNAME"` row and update the `"ROTATE"` row:
```markdown
| `"SRV"` | Tunnel over SRV queries/answers — payload rides in the SRV target name and the priority/weight/port fields; use when the other record types are filtered |
| `"ROTATE"` | Random TXT/NS/CNAME/SRV mix per query, so the stream does not look like a single-type DNS tunnel |
```
   - Replace the note at line 201:
```markdown
`"NS"`, `"CNAME"`, `"SRV"`, and `"ROTATE"` require a server running the same feature version. An older server answers NS, CNAME, and SRV tunnel queries with an empty response, which surfaces as repeated session-init retries — switch back to `"TXT"` if your server has not been updated.
```
   - Replace the FAQ paragraph at line 683:
```markdown
If tunnel queries never get answers while normal lookups work, some resolver or middlebox in your path may block or mangle TXT queries/answers. Switch the client to NS, CNAME, or SRV queries (see `DNS_QUERY_TYPE` under [DNS Delegation Details](#dns-delegation-details)); the same delegation records work unchanged. These modes need a server that mirrors the question type, so update the server first.
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/config/client.go internal/config/client_test.go client_config.toml.simple README.MD
git commit -m "feat: accept SRV in DNS_QUERY_TYPE client config"
```

---

### Task 5: Client picks SRV + 4-way ROTATE

**Files:**
- Modify: `internal/client/tunnel_query.go` (`pickTunnelQueryType`)
- Modify: `internal/client/tunnel_query_test.go`

**Interfaces:**
- Consumes: Task 4 `cfg.DNSQueryType`.
- Produces: `func (c *Client) pickTunnelQueryType() uint16` — `TXT`→16, `NS`→2, `CNAME`→5, `SRV`→33, `ROTATE`→uniform random over the four (`math/rand`), empty/unknown → 16. All question-building callers unchanged.

- [x] **Step 1: Write the failing tests**

In `internal/client/tunnel_query_test.go`:

1. Update `TestPickTunnelQueryTypeRotateMix` to require all four types (keep the function name and map-based shape):
```go
func TestPickTunnelQueryTypeRotateMix(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "ROTATE"
	seen := map[uint16]bool{}
	for i := 0; i < 400; i++ {
		seen[c.pickTunnelQueryType()] = true
	}
	for _, want := range []uint16{
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_NS,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_SRV,
	} {
		if !seen[want] {
			t.Fatalf("ROTATE must produce type %d, got %v", want, seen)
		}
	}
}
```
2. Add after `TestPickTunnelQueryTypeCNAMEMode`:
```go
func TestPickTunnelQueryTypeSRVMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "SRV"
	if got := c.pickTunnelQueryType(); got != Enums.DNS_RECORD_TYPE_SRV {
		t.Fatalf("SRV mode picked %d", got)
	}
}
```
3. Add after `TestBuildTunnelQuestionBytesUsesCNAMEMode`:
```go
func TestBuildTunnelQuestionBytesUsesSRVMode(t *testing.T) {
	c := &Client{}
	c.cfg.DNSQueryType = "SRV"
	packet, err := c.buildTunnelQuestionBytes("v.example.com", []byte("abcdefgh"))
	if err != nil {
		t.Fatal(err)
	}
	if got := questionTypeOf(t, packet); got != Enums.DNS_RECORD_TYPE_SRV {
		t.Fatalf("packet qtype = %d, want SRV", got)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryTypeSRVMode|TestPickTunnelQueryTypeRotateMix|TestBuildTunnelQuestionBytesUsesSRVMode' -v`
Expected: FAIL — SRV mode picks TXT; ROTATE never sees SRV; packet qtype is TXT.

- [x] **Step 3: Implement**

In `internal/client/tunnel_query.go`, replace `pickTunnelQueryType`:
```go
// pickTunnelQueryType returns the DNS record type for the next tunnel query
// based on the configured mode: TXT (default), NS, CNAME, SRV, or ROTATE
// (uniform random over the four).
func (c *Client) pickTunnelQueryType() uint16 {
	mode := "TXT"
	if c != nil {
		mode = strings.TrimSpace(c.cfg.DNSQueryType)
		if mode == "" {
			mode = "TXT"
		}
	}
	switch mode {
	case "NS":
		return Enums.DNS_RECORD_TYPE_NS
	case "CNAME":
		return Enums.DNS_RECORD_TYPE_CNAME
	case "SRV":
		return Enums.DNS_RECORD_TYPE_SRV
	case "ROTATE":
		switch rand.Intn(4) {
		case 0:
			return Enums.DNS_RECORD_TYPE_TXT
		case 1:
			return Enums.DNS_RECORD_TYPE_NS
		case 2:
			return Enums.DNS_RECORD_TYPE_CNAME
		default:
			return Enums.DNS_RECORD_TYPE_SRV
		}
	default:
		return Enums.DNS_RECORD_TYPE_TXT
	}
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/ -run 'TestPickTunnelQueryType|TestBuildTunnelQuestionBytesUses' -v`
Expected: PASS.

Then client package regression:
Run: `go test ./internal/client/`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/client/tunnel_query.go internal/client/tunnel_query_test.go
git commit -m "feat: per-query tunnel DNS type selection (TXT/NS/CNAME/SRV/ROTATE)"
```

---

### Task 6: Server-side smoke test (udpserver) + full verification

**Files:**
- Test: `internal/udpserver/srv_tunnel_test.go` (new, mirrors `cname_tunnel_test.go`)

**Interfaces:**
- Consumes: everything above via public API (`BuildVPNResponsePacket`, `ExtractVPNResponse`, `Matcher`, `Server.handleMTUDownRequest`). Reuses `patternBytes` and the `Server` fixture style already in `cname_tunnel_test.go` (same package).

- [x] **Step 1: Write the test**

Create `internal/udpserver/srv_tunnel_test.go`:

```go
// ==============================================================================
// StormDNS
// Author: nullroute1970
// Github: https://github.com/nullroute1970/StormDNS
// Year: 2026
// ==============================================================================
package udpserver

import (
	"encoding/binary"
	"sync"
	"testing"

	DnsParser "stormdns-go/internal/dnsparser"
	domainMatcher "stormdns-go/internal/domainmatcher"
	Enums "stormdns-go/internal/enums"
	VpnProto "stormdns-go/internal/vpnproto"
)

func TestSRVTunnelQueryAcceptedEndToEnd(t *testing.T) {
	// 1. An SRV-type tunnel query for a data-bearing name passes the matcher.
	matcher := domainMatcher.New([]string{"v.example.com"}, 3)
	query, err := DnsParser.BuildTunnelTXTQuestionPacket("abc.v.example.com", []byte("q3f2abc"), Enums.DNS_RECORD_TYPE_SRV, 0)
	if err != nil {
		t.Fatal(err)
	}
	lite, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		t.Fatal(err)
	}
	decision := matcher.Match(lite)
	if decision.Action != domainMatcher.ActionProcess {
		t.Fatalf("SRV tunnel query rejected: action=%v reason=%s", decision.Action, decision.Reason)
	}

	// 2. The real server response handler mirrors the question type into an
	//    SRV RRset: every record owns the qname, payload in target + fields.
	s := &Server{
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				return make([]byte, mtuProbeMaxDownSize)
			},
		},
	}

	downloadSize := 300 // forces multi-record SRV framing
	payload := make([]byte, mtuProbeDownMinSize+downloadSize)
	payload[0] = mtuProbeModeRaw
	copy(payload[1:1+mtuProbeCodeLength], []byte{9, 8, 7, 6})
	binary.BigEndian.PutUint16(payload[mtuProbeUpMinSize:mtuProbeDownMinSize], uint16(downloadSize))
	copy(payload[mtuProbeDownMinSize:], patternBytes(downloadSize))

	response := s.handleMTUDownRequest(query, lite, decision, VpnProto.Packet{
		SessionID:   9,
		PacketType:  Enums.PACKET_MTU_DOWN_REQ,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	})
	if response == nil {
		t.Fatal("expected response packet")
	}

	parsed, err := DnsParser.ParsePacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Answers) < 2 {
		t.Fatalf("expected multiple SRV answers, got %d", len(parsed.Answers))
	}
	for i, ans := range parsed.Answers {
		if ans.Type != Enums.DNS_RECORD_TYPE_SRV {
			t.Fatalf("answer %d type = %d, want SRV", i, ans.Type)
		}
		if ans.Name != "abc.v.example.com" {
			t.Fatalf("answer %d owner = %q, want qname", i, ans.Name)
		}
		if len(ans.RData) < 7 {
			t.Fatalf("answer %d rdata too short: %v", i, ans.RData)
		}
	}

	// 3. The client-side extractor recovers the payload from the RRset.
	packet, err := DnsParser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_DOWN_RES {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, Enums.PACKET_MTU_DOWN_RES)
	}
	if len(packet.Payload) != downloadSize {
		t.Fatalf("unexpected payload len: got=%d want=%d", len(packet.Payload), downloadSize)
	}
	if got := packet.Payload[:mtuProbeCodeLength]; string(got) != string([]byte{9, 8, 7, 6}) {
		t.Fatalf("unexpected probe code: got=%v", got)
	}
}
```

- [x] **Step 2: Run test to verify it passes**

Run: `go test ./internal/udpserver/ -run TestSRVTunnelQueryAcceptedEndToEnd -v`
Expected: PASS (integration gate; if it fails, debug per systematic-debugging — most likely a framing mismatch caught only by cross-package use).

- [x] **Step 3: Full verification**

Run:
```bash
gofmt -l .                       # expect no output
go vet ./...
go build ./cmd/client && go build ./cmd/server
go test -timeout 300s ./...
go test -race ./internal/dnsparser/ ./internal/domainmatcher/ ./internal/config/ ./internal/client/ ./internal/udpserver/
```
Expected: all PASS.

- [x] **Step 4: Manual smoke (optional, environment permitting)**

`go run scripts/bench/bench.go` runs a local server+client; do one TXT run (regression). For an SRV smoke, temporarily set `DNS_QUERY_TYPE = "SRV"` in the bench's client config before running — confirm throughput > 0 and no `ErrTXTAnswerMissing` storms. Not required for merge.

- [x] **Step 5: Commit**

```bash
git add internal/udpserver/srv_tunnel_test.go
git commit -m "test: SRV tunnel query acceptance end to end"
```

---

## Self-Review Notes (checked)

- **Spec coverage:** fixed-byte channel (T2 `buildSRVAnswerRData`/`decodeNameRDataUnit`), NS-style framing (T2 `BuildSRVResponsePacket`), ≥6-byte unit guarantee + rebalance (T2 `buildNameAnswerUnits` + barrage test), root-target decode (T1 parser + T2 `decodeNameRDataUnit`), degenerate <6 fallback (T2 `buildSRVVPNResponse` + test), parser offset 6 (T1), capacities pinned (T2 `TestSRVUnitCapacityIsNSCapacityPlusSix`), matcher (T3), config+docs (T4), client mode + 4-way ROTATE (T5), integration (T6), old-server compatibility documented (T4), TXT/NS/CNAME untouched except the chunk-core extraction (T2, NS tests are the regression lock).
- **No placeholders:** every step has concrete code, exact insertion points, and runnable verification with expected outcomes.
- **Type consistency:** `nameRDataNameOffset`, `maxSRVUnitBytes`, `buildNameAnswerUnits`, `buildSRVAnswerRData`, `buildSRVAnswerChunks`, `questionTypeIsSRV`, `buildSRVVPNResponse`, `buildSingleSRVResponsePacket`, `BuildSRVResponsePacket`, `decodeNameRDataUnit` are named and typed identically across tasks. Existing exported names unchanged. Test helpers `buildSRVAnswerTestPacket`, `srvRData`, `patternedPayload`, `splitLabels`, `vpnPacketForTest` (dnsparser), `patternBytes` (udpserver), `writeClientConfigForTest` (config), `litePacketWithQuestion` (domainmatcher), `questionTypeOf` (client) are defined in their packages and reused, never redefined.
- **Edge case in the plan:** Task 1's note about imports keeps the new test file compiling before Task 2 appends the tests that use `errors`/`VpnProto`.

---

## Execution Notes (as built)

All six tasks complete. Commits: `43cb242` (parser), `207844f` (transport/extraction), `b7594cb` (matcher), `67c8020` (config+docs), `dbe7466` (client picker + 4-way ROTATE), `be67665` (udpserver e2e).

Deviations from the written steps, all reflected in the committed code and tests:

1. **Root name representation.** `parseName` returns `"."` for the DNS root (`if !hasLabel { return ".", ... }`), not `""` — the spec's decision 6 wording assumed `""`. Extraction uses `isRootRDataName(name)` which accepts both `""` (unset/undecodable) and `"."` (root). The Task 1 root test asserts `got != "" && got != "."`, and `decodeNameRDataUnit` only treats an SRV root target as a six-byte unit when the rdata is exactly `len == 7 && RData[6] == 0`.
2. **Task 6 owner assertion.** The plan snippet compared SRV owners to the base tunnel name `abc.v.example.com`; the real question name is `q3f2abc.abc.v.example.com` (payload labels + base domain), which is what the server mirrors. The committed test asserts every SRV answer owns `parsed.Questions[0].Name` (the echoed question name), which is the NS-style invariant.

Environment limits observed while verifying:

- `go test -race` cannot run on this Windows host (no gcc/cgo). All packages pass without `-race`; CI on Linux should run the race command from Task 6 Step 3.
- `gofmt -l` flags files repo-wide because of pre-existing UTF-8 BOM + CRLF working-tree endings. Per-file verification used `gofmt <file>` compared against the LF/BOM-normalized file: all touched files are format-clean except `internal/config/client.go`, whose 224-line struct-alignment diff predates this work (228 diff lines before the change) and is out of scope.
- SRV `gofmt` gate result: `internal/dnsparser/{transport,parser,srv_test}.go`, `internal/domainmatcher/{matcher,matcher_test}.go`, `internal/config/client_test.go`, `internal/client/tunnel_query{.go,_test.go}`, `internal/udpserver/srv_tunnel_test.go` all clean.
- Verification evidence: `go vet ./...` clean; `go build ./cmd/client && go build ./cmd/server` OK; `go test -timeout 300s ./...` → 17 packages `ok`; `internal/dnsparser` 61 tests pass including the 601-size chunk-boundary barrage; `TestSRVTunnelQueryAcceptedEndToEnd` passes.
