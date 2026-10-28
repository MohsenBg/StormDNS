package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"stormdns-go/internal/config"
	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
	"stormdns-go/internal/logger"
	"stormdns-go/internal/security"
	VpnProto "stormdns-go/internal/vpnproto"
)

type autoTestResolver struct {
	mu               sync.Mutex
	allowed          map[uint16]bool
	counts           map[uint16]int
	maxUp, maxDown   int
	empty, wrongCode bool
	wrongAfter       int
	rcode            byte
	responsePolicy   func(uint16, int) (bool, bool, int, int)
	delay            time.Duration
	addr             *net.UDPAddr
}

func newAutoTestResolver(t *testing.T, types ...uint16) *autoTestResolver {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &autoTestResolver{allowed: map[uint16]bool{}, counts: map[uint16]int{}, maxUp: 512, maxDown: 4000, addr: socket.LocalAddr().(*net.UDPAddr)}
	for _, q := range types {
		r.allowed[q] = true
	}
	codec, err := security.NewCodec(1, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { socket.Close(); <-done })
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := socket.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			query := buffer[:n]
			lite, err := DnsParser.ParsePacketLite(query)
			if err != nil || !lite.HasQuestion {
				continue
			}
			q := lite.FirstQuestion
			r.mu.Lock()
			r.counts[q.Type]++
			allowed, empty, wrong, up, down, delay := r.allowed[q.Type], r.empty, r.wrongCode, r.maxUp, r.maxDown, r.delay
			wrong = wrong || (r.wrongAfter > 0 && r.counts[q.Type] > r.wrongAfter)
			rcode := r.rcode
			policy, queryIndex := r.responsePolicy, r.counts[q.Type]
			r.mu.Unlock()
			if policy != nil {
				drop, badNonce, capUp, capDown := policy(q.Type, queryIndex)
				if drop {
					continue
				}
				wrong = wrong || badNonce
				if capUp > 0 {
					up = capUp
				}
				if capDown > 0 {
					down = capDown
				}
			}
			if !allowed {
				continue
			}
			if empty {
				reply, _ := DnsParser.BuildEmptyNoErrorResponse(query)
				socket.WriteToUDP(reply, peer)
				continue
			}
			labels := strings.ReplaceAll(strings.TrimSuffix(q.Name, ".v.example.com"), ".", "")
			packet, err := VpnProto.ParseFromLabels(labels, codec)
			if err != nil || len(packet.Payload) < 7 {
				continue
			}
			var payload []byte
			var kind uint8
			switch packet.PacketType {
			case Enums.PACKET_MTU_UP_REQ:
				if len(packet.Payload) > up {
					continue
				}
				payload = make([]byte, 6)
				kind = Enums.PACKET_MTU_UP_RES
				binary.BigEndian.PutUint16(payload[4:6], uint16(len(packet.Payload)))
			case Enums.PACKET_MTU_DOWN_REQ:
				size := int(binary.BigEndian.Uint16(packet.Payload[5:7]))
				if len(packet.Payload) > up || size > down {
					continue
				}
				payload = make([]byte, size)
				kind = Enums.PACKET_MTU_DOWN_RES
				binary.BigEndian.PutUint16(payload[4:6], uint16(size))
			default:
				continue
			}
			copy(payload[:4], packet.Payload[1:5])
			if wrong {
				payload[0] ^= 1
			}
			reply, err := DnsParser.BuildVPNResponsePacket(query, q.Name, VpnProto.Packet{SessionID: 255, PacketType: kind, StreamID: 1, SequenceNum: 1, Payload: payload}, packet.Payload[0] == 1)
			if err == nil {
				reply[3] |= rcode
				if delay > 0 {
					time.Sleep(delay)
				}
				socket.WriteToUDP(reply, peer)
			}
		}
	}()
	return r
}

func newAutoTestClient(t *testing.T, resolvers ...*autoTestResolver) *Client {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "client_config.toml")
	settings := `DOMAINS = ["v.example.com"]
ENCRYPTION_KEY = "test-key"
DATA_ENCRYPTION_METHOD = 1
MIN_UPLOAD_MTU = 20
MAX_UPLOAD_MTU = 60
MIN_DOWNLOAD_MTU = 40
MAX_DOWNLOAD_MTU = 100
MTU_TEST_TIMEOUT_RESOLVERS = 0.04
MTU_TEST_RETRIES_RESOLVERS = 1
MTU_TEST_PARALLELISM_RESOLVERS = 2
DNS_AUTO_PROBE_COUNT = 3
DNS_AUTO_SWITCH_CONFIRMATION_COUNT = 2
DNS_AUTO_RECHECK_JITTER_PERCENT = 0
`
	if err := os.WriteFile(path, []byte(settings), 0600); err != nil {
		t.Fatal(err)
	}
	var endpoints []string
	for _, r := range resolvers {
		endpoints = append(endpoints, fmt.Sprintf("127.0.0.1:%d", r.addr.Port))
	}
	if err := os.WriteFile(filepath.Join(dir, "client_resolvers.txt"), []byte(strings.Join(endpoints, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// The resolver-file loader deduplicates IPs. These local test endpoints
	// deliberately share an IP, so preserve their distinct ports explicitly.
	cfg.Resolvers = nil
	for _, r := range resolvers {
		cfg.Resolvers = append(cfg.Resolvers, config.ResolverAddress{IP: "127.0.0.1", Port: r.addr.Port})
	}
	cfg.DNSQueryType = "AUTO"
	codec, err := security.NewCodec(1, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	c := New(cfg, logger.New("auto-test", "error"), codec)
	if err := c.BuildConnectionMap(); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAutoStartupSelectsPerResolver(t *testing.T) {
	txt := newAutoTestResolver(t, Enums.DNS_RECORD_TYPE_TXT)
	srv := newAutoTestResolver(t, Enums.DNS_RECORD_TYPE_SRV)
	c := newAutoTestClient(t, txt, srv)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.balancer.ValidCount(); got != 2 {
		for key, state := range c.autoQueryStates {
			t.Logf("%s: %+v", key, state.results)
		}
		t.Fatalf("AUTO must discover both TXT-only and SRV-only paths, got %d", got)
	}
	for i, want := range []uint16{Enums.DNS_RECORD_TYPE_TXT, Enums.DNS_RECORD_TYPE_SRV} {
		conn, ok := c.GetConnectionByKey(c.connections[i].Key)
		if !ok || conn.TunnelQueryType != want {
			t.Fatalf("path %d type=%d, want %d", i, conn.TunnelQueryType, want)
		}
		packet, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, make([]byte, 10), c.tunnelQueryType(conn))
		if err != nil || questionTypeOf(t, packet) != want {
			t.Fatalf("session query did not use selected type: %v", err)
		}
	}
}

func TestAutoRankingAndSwitchThresholds(t *testing.T) {
	c := newAutoTestClient(t, newAutoTestResolver(t, Enums.DNS_RECORD_TYPE_TXT))
	result := func(q uint16, successes int, elapsed time.Duration) autoQueryResult {
		return autoQueryResult{queryType: q, mtu: mtuConnectionProbeResult{UploadBytes: 60, DownloadBytes: 100}, successes: successes, attempts: 5, elapsed: elapsed}
	}
	stable := result(16, 5, time.Second)
	fast := result(33, 4, time.Millisecond)
	if got := c.rankAutoQueryResults([]autoQueryResult{fast, stable}); len(got) != 2 || got[0].queryType != 16 {
		t.Fatalf("reliability must beat speed: %+v", got)
	}
	if c.autoQueryImproves(fast, stable) {
		t.Fatal("less reliable candidate must not replace the incumbent")
	}
	equal := result(33, 5, time.Second)
	if c.autoQueryImproves(equal, stable) {
		t.Fatal("equal candidate must not cause a switch")
	}
	tooSmall := result(33, 5, 900*time.Millisecond)
	if c.autoQueryImproves(tooSmall, stable) {
		t.Fatal("11% improvement must not meet the 20% threshold")
	}
	better := result(33, 5, 800*time.Millisecond)
	if !c.autoQueryImproves(better, stable) {
		t.Fatal("25% speed improvement must allow a switch")
	}
	c.cfg.DNSAutoMinSuccessPercent = 90
	if got := c.rankAutoQueryResults([]autoQueryResult{fast, stable}); len(got) != 1 || got[0].queryType != 16 {
		t.Fatalf("minimum success percentage ignored: %+v", got)
	}
	if got := c.rankAutoQueryResults([]autoQueryResult{equal, stable}); got[0].queryType != 33 {
		t.Fatal("exact ties must preserve candidate order")
	}
}

func TestAutoStartupRejectsInvalidResponses(t *testing.T) {
	for _, kind := range []string{"empty", "wrong nonce"} {
		t.Run(kind, func(t *testing.T) {
			r := newAutoTestResolver(t, 16, 2, 5, 33)
			r.mu.Lock()
			r.empty = kind == "empty"
			r.wrongCode = kind == "wrong nonce"
			r.mu.Unlock()
			c := newAutoTestClient(t, r)
			if err := c.RunInitialMTUTests(context.Background()); err == nil || c.balancer.ValidCount() != 0 {
				t.Fatalf("invalid tunnel response must fail discovery: %v", err)
			}
		})
	}
}

func TestAutoUsesOnlyConfiguredCandidates(t *testing.T) {
	r := newAutoTestResolver(t, 16, 33)
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoQueryTypes = []string{"SRV"}
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := c.connections[0].TunnelQueryType; got != 33 {
		t.Fatalf("selected unconfigured type %d", got)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts[16] != 0 {
		t.Fatal("TXT was probed despite being excluded")
	}
}

func TestAutoCancellationClosesProbeSocket(t *testing.T) {
	r := newAutoTestResolver(t)
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoProbeTimeoutSeconds = 5
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.RunInitialMTUTests(ctx); err == nil {
		t.Fatal("cancelled discovery unexpectedly succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation waited for the five-second probe timeout")
	}
}

func TestAutoSwitchDoesNotRestartSession(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := c.connections[0]
	c.sessionID = 7
	c.sessionReady = true
	r.mu.Lock()
	r.allowed = map[uint16]bool{33: true}
	r.mu.Unlock()
	c.checkAutoQueryPath(context.Background(), before, before.QueryTypeGeneration)
	after, _ := c.GetConnectionByKey(before.Key)
	if !after.IsValid || after.TunnelQueryType != 33 || after.QueryTypeGeneration == before.QueryTypeGeneration {
		t.Fatalf("path did not switch to SRV: %+v", after)
	}
	if c.syncedUploadMTU != 60 || c.syncedDownloadMTU != 100 || c.runtimeResetPending.Load() || c.sessionID != 7 || !c.sessionReady {
		t.Fatal("compatible switch changed session state")
	}
}

func TestAutoSmallerMTURecoveryPolicy(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprint(allow), func(t *testing.T) {
			r := newAutoTestResolver(t, 16)
			c := newAutoTestClient(t, r)
			if err := c.RunInitialMTUTests(context.Background()); err != nil {
				t.Fatal(err)
			}
			conn := c.connections[0]
			c.cfg.DNSAutoAllowMTURestart = allow
			r.mu.Lock()
			r.allowed = map[uint16]bool{33: true}
			r.maxUp = 30
			r.maxDown = 50
			r.mu.Unlock()
			c.checkAutoQueryPath(context.Background(), conn, conn.QueryTypeGeneration)
			if c.balancer.ValidCount() != 0 {
				t.Fatal("smaller-MTU path was published into a running session")
			}
			if c.autoMTURescanPending.Load() != allow || c.runtimeResetPending.Load() != allow {
				t.Fatalf("restart policy ignored: allow=%v requested=%v", allow, c.runtimeResetPending.Load())
			}
			if c.syncedUploadMTU != 60 || c.syncedDownloadMTU != 100 {
				t.Fatal("background worker changed session MTU")
			}
		})
	}
}

func TestAutoDoesNotRestartWhileAnotherPathWorks(t *testing.T) {
	bad, healthy := newAutoTestResolver(t, 16), newAutoTestResolver(t, 33)
	c := newAutoTestClient(t, bad, healthy)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	bad.mu.Lock()
	bad.maxUp = 25
	bad.mu.Unlock()
	c.checkAutoQueryPath(context.Background(), conn, conn.QueryTypeGeneration)
	if c.balancer.ValidCount() != 1 || c.runtimeResetPending.Load() {
		t.Fatal("AUTO restarted despite a compatible healthy path")
	}
}

func TestAutoEmptyRepliesAndOldGenerations(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	query, err := c.buildTunnelQuestionBytes(conn.Domain, []byte("hello"), conn.TunnelQueryType)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.trackResolverSend(query, r.addr.String(), "local", conn.Key, now, conn.QueryTypeGeneration)
	empty, _ := DnsParser.BuildEmptyNoErrorResponse(query)
	c.handleInboundPacket(empty, r.addr, "local")
	s := c.autoQueryStates[conn.Key]
	if s.failures != 1 {
		t.Fatal("empty DNS answer must count as a failed AUTO request")
	}
	c.noteAutoQueryOutcome(conn.Key, 33, conn.QueryTypeGeneration, true, now)
	c.noteAutoQueryOutcome(conn.Key, 16, conn.QueryTypeGeneration+1, true, now)
	if s.failures != 1 {
		t.Fatal("wrong type or obsolete generation changed the current health state")
	}
	c.noteAutoQueryOutcome(conn.Key, 16, conn.QueryTypeGeneration, true, now)
	if s.failures != 0 {
		t.Fatal("valid current response must reset consecutive failures")
	}
	c.trackResolverSend(query, r.addr.String(), "local", conn.Key, now, conn.QueryTypeGeneration)
	c.collectExpiredResolverTimeouts(now.Add(c.resolverRequestTimeout() + time.Second))
	if s.failures != 1 {
		t.Fatal("request timeout was not attributed to the selected type")
	}
}

func TestAutoSchedulerLimitsCooldownAndCancellation(t *testing.T) {
	a, b := newAutoTestResolver(t, 16), newAutoTestResolver(t, 33)
	c := newAutoTestClient(t, a, b)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.cfg.DNSAutoRecheckParallelism = 1
	now := time.Now()
	c.runAutoQueryChecks(context.Background(), now)
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			t.Fatal("healthy path was rechecked before its interval")
		}
	}
	c.cfg.DNSAutoRecheckEnabled = false
	for _, s := range c.autoQueryStates {
		s.failures = 3
		s.lastFailureCheck = now
	}
	c.runAutoQueryChecks(context.Background(), now.Add(29*time.Second))
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			t.Fatal("failure cooldown was ignored")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.runAutoQueryChecks(ctx, now.Add(30*time.Second))
	c.autoQueryMu.Lock()
	active := 0
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			active++
		}
	}
	c.autoQueryMu.Unlock()
	if active != 1 {
		cancel()
		c.asyncWG.Wait()
		t.Fatalf("expected one admitted worker, got %d", active)
	}
	cancel()
	c.asyncWG.Wait()
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			t.Fatal("cancelled worker remained in flight")
		}
	}
}

func TestAutoEncoderUsesPerTypeCacheAndLatestSelection(t *testing.T) {
	a, b := newAutoTestResolver(t, 16), newAutoTestResolver(t, 33)
	c := newAutoTestClient(t, a, b)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.asyncWG.Add(1)
	go c.asyncEncodeWorker(ctx, 0)
	defer func() { cancel(); c.asyncWG.Wait() }()
	encode := func(conns []Connection) encodedOutboundTask {
		c.txChannel <- rawOutboundTask{wasPacked: true, opts: VpnProto.BuildOptions{PacketType: Enums.PACKET_PING, SessionID: 1}, conns: conns}
		select {
		case out := <-c.encodedTXChannel:
			return out
		case <-time.After(time.Second):
			t.Fatal("encoder produced no packet")
			return encodedOutboundTask{}
		}
	}
	stale := append([]Connection(nil), c.connections...)
	out := encode(stale)
	if len(out.frames) != 2 || questionTypeOf(t, out.frames[0].packet) != 16 || questionTypeOf(t, out.frames[1].packet) != 33 {
		t.Fatal("domain-only packet reuse overwrote a resolver's selected type")
	}
	updated := stale[0]
	updated.TunnelQueryType = 5
	updated.QueryTypeGeneration++
	c.balancer.SetConnectionTransport(updated)
	out = encode(stale[:1])
	if len(out.frames) != 1 || questionTypeOf(t, out.frames[0].packet) != 5 || out.frames[0].queryGeneration != updated.QueryTypeGeneration {
		t.Fatal("encoder used a stale task's query type or generation")
	}
}

func TestAutoPeriodicIntervalAndJitter(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoQueryTypes = []string{"TXT"}
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.cfg.DNSAutoFailureRecheckEnabled = false
	now := time.Now()
	if got := c.nextAutoQueryCheck("a", now); !got.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("default interval must be 15 minutes: %s", got.Sub(now))
	}
	c.cfg.DNSAutoRecheckJitterPercent = 10
	for _, key := range []string{"a", "b", "c"} {
		due := c.nextAutoQueryCheck(key, now)
		delta := due.Sub(now)
		if delta < 810*time.Second || delta > 990*time.Second {
			t.Fatalf("jitter out of bounds: %s", delta)
		}
	}
	c.cfg.DNSAutoRecheckJitterPercent = 0
	s := c.autoQueryStates[c.connections[0].Key]
	s.nextAt = now.Add(15 * time.Minute)
	c.runAutoQueryChecks(context.Background(), now.Add(899*time.Second))
	if s.inFlight {
		t.Fatal("periodic scan ran early")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.runAutoQueryChecks(ctx, now.Add(900*time.Second))
	c.autoQueryMu.Lock()
	started := s.inFlight
	c.autoQueryMu.Unlock()
	cancel()
	c.asyncWG.Wait()
	if !started {
		t.Fatal("periodic scanning was incorrectly tied to failure scanning")
	}
}

func TestAutoDoesNotPublishCancelledOrObsoleteCheck(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := c.connections[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.checkAutoQueryPath(ctx, before, before.QueryTypeGeneration)
	after, _ := c.GetConnectionByKey(before.Key)
	if !after.IsValid || after.TunnelQueryType != before.TunnelQueryType {
		t.Fatal("cancelled check disabled a healthy path")
	}
	c.autoQueryStates[before.Key].generation++
	r.mu.Lock()
	r.allowed = map[uint16]bool{33: true}
	r.mu.Unlock()
	c.checkAutoQueryPath(context.Background(), before, before.QueryTypeGeneration)
	after, _ = c.GetConnectionByKey(before.Key)
	if after.TunnelQueryType != before.TunnelQueryType {
		t.Fatal("obsolete worker published after the selection generation changed")
	}
}

func TestAutoSchedulerServesOldestDuePath(t *testing.T) {
	a, b := newAutoTestResolver(t, 16), newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, a, b)
	c.cfg.DNSAutoQueryTypes = []string{"TXT"}
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.cfg.DNSAutoFailureRecheckEnabled = false
	c.cfg.DNSAutoRecheckParallelism = 1
	var keys []string
	for key := range c.autoQueryStates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	now := time.Now()
	c.autoQueryStates[keys[0]].nextAt = now.Add(-time.Hour)
	c.autoQueryStates[keys[1]].nextAt = now.Add(-2 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	c.runAutoQueryChecks(ctx, now)
	c.autoQueryMu.Lock()
	oldestStarted := c.autoQueryStates[keys[1]].inFlight
	c.autoQueryMu.Unlock()
	cancel()
	c.asyncWG.Wait()
	if !oldestStarted {
		t.Fatal("scheduler favored lexical key order over the oldest due path")
	}
}

func TestAutoReconnectRechecksWithoutRuntimeOrMTURestart(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	conn.IsValid = false
	c.balancer.SetConnectionTransport(conn)
	c.cfg.DNSAutoAllowMTURestart = false
	r.mu.Lock()
	r.allowed = map[uint16]bool{33: true}
	r.mu.Unlock()
	c.recheckAutoPathsForSession(context.Background())
	after, _ := c.GetConnectionByKey(conn.Key)
	if !after.IsValid || after.TunnelQueryType != 33 || c.runtimeResetPending.Load() || c.syncedUploadMTU != 60 {
		t.Fatal("reconnect relied on a stopped health loop or changed MTU")
	}
}

func TestAutoProbeCountAndTimeoutOverride(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	r.mu.Lock()
	r.delay = 5 * time.Millisecond
	r.mu.Unlock()
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoQueryTypes = []string{"TXT"}
	c.cfg.DNSAutoProbeCount = 2
	c.cfg.DNSAutoProbeTimeoutSeconds = 0.2
	c.mtuTestTimeout = time.Millisecond
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatalf("AUTO timeout did not override the active MTU timeout: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts[16] != 6 {
		t.Fatalf("want 2 discovery requests and 2 independent bidirectional rounds, got %d requests", r.counts[16])
	}
}

func TestAutoSwitchConfirmationCount(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			r := newAutoTestResolver(t, 16)
			c := newAutoTestClient(t, r)
			if err := c.RunInitialMTUTests(context.Background()); err != nil {
				t.Fatal(err)
			}
			conn := c.connections[0]
			c.cfg.DNSAutoSwitchConfirmationCount = count
			r.mu.Lock()
			r.allowed = map[uint16]bool{33: true}
			clear(r.counts)
			r.mu.Unlock()
			c.checkAutoQueryPath(context.Background(), conn, conn.QueryTypeGeneration)
			r.mu.Lock()
			defer r.mu.Unlock()
			if got, want := r.counts[33], 2*(3+count); got != want {
				t.Fatalf("confirmation rounds ignored: got %d requests, want %d", got, want)
			}
		})
	}
}

func TestAutoFailedConfirmationDoesNotPublishCandidate(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	c.cfg.DNSAutoAllowMTURestart = false
	r.mu.Lock()
	r.allowed = map[uint16]bool{33: true}
	clear(r.counts)
	r.wrongAfter = 6
	r.mu.Unlock()
	c.checkAutoQueryPath(context.Background(), conn, conn.QueryTypeGeneration)
	after, _ := c.GetConnectionByKey(conn.Key)
	if after.IsValid || after.TunnelQueryType != 16 {
		t.Fatal("candidate that failed confirmation was published")
	}
}

func TestAutoSupportsBaseEncodedNameResponses(t *testing.T) {
	r := newAutoTestResolver(t, 2, 5, 33)
	c := newAutoTestClient(t, r)
	c.cfg.BaseEncodeData = true
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	results := c.autoQueryStates[c.connections[0].Key].results
	for _, r := range results {
		if r.queryType != 16 && !c.autoQueryUsable(r) {
			t.Fatalf("name transport failed with BASE_ENCODE_DATA: %+v", r)
		}
	}
}

func TestAutoOlderTimeoutsDoNotUndoNewerSuccess(t *testing.T) {
	c := newAutoTestClient(t, newAutoTestResolver(t, 16))
	c.cfg.DNSAutoQueryTypes = []string{"TXT"}
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	now := time.Now()
	c.noteAutoQueryOutcome(conn.Key, 16, conn.QueryTypeGeneration, true, now)
	for i := 0; i < 3; i++ {
		c.noteAutoQueryOutcome(conn.Key, 16, conn.QueryTypeGeneration, false, now.Add(-time.Second))
	}
	if c.autoQueryStates[conn.Key].failures != 0 {
		t.Fatal("delayed timeout accounting undid a newer successful tunnel response")
	}
}

func TestAutoRejectsDNSErrorsWithValidTunnelPayload(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	r.mu.Lock()
	r.rcode = 3
	r.mu.Unlock()
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoQueryTypes = []string{"TXT"}
	if err := c.RunInitialMTUTests(context.Background()); err == nil {
		t.Fatal("DNS error response qualified despite its nonzero RCODE")
	}
}

func TestAutoRecoveryPrefersAnyCompatibleTypeBeforeSmallerMTU(t *testing.T) {
	r := newAutoTestResolver(t, 16)
	c := newAutoTestClient(t, r)
	c.cfg.DNSAutoQueryTypes = []string{"TXT", "SRV"}
	if err := c.RunInitialMTUTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn := c.connections[0]
	r.mu.Lock()
	r.allowed = map[uint16]bool{16: true, 33: true}
	clear(r.counts)
	r.responsePolicy = func(q uint16, n int) (bool, bool, int, int) {
		// The first current-MTU comparison loses every sample. A subsequent
		// full scan finds reliable but smaller TXT and a less reliable SRV
		// candidate that can still carry the negotiated MTU.
		if n <= 6 {
			return true, false, 0, 0
		}
		if q == 16 {
			return false, false, 30, 50
		}
		return false, n >= 11 && n <= 14, 0, 0
	}
	r.mu.Unlock()
	c.checkAutoQueryPath(context.Background(), conn, conn.QueryTypeGeneration)
	after, _ := c.GetConnectionByKey(conn.Key)
	if !after.IsValid || after.TunnelQueryType != 33 || c.runtimeResetPending.Load() {
		t.Fatalf("compatible SRV was overlooked in favor of smaller TXT: %+v", after)
	}
}
