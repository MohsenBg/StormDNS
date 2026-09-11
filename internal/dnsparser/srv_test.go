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
	if got := parsed.Answers[0].RDataName; got != "" && got != "." {
		t.Fatalf("root target must decode to the root/empty name, got %q", got)
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
