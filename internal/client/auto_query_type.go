package client

import (
	"context"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	DnsParser "stormdns-go/internal/dnsparser"
	Enums "stormdns-go/internal/enums"
)

type autoQueryResult struct {
	queryType           uint16
	mtu                 mtuConnectionProbeResult
	successes, attempts int
	elapsed             time.Duration
}

func (r autoQueryResult) speed() float64 {
	if r.successes == 0 || r.elapsed <= 0 {
		return 0
	}
	return float64(r.successes*(r.mtu.UploadBytes+r.mtu.DownloadBytes)) / r.elapsed.Seconds()
}

type autoQueryState struct {
	selected                          autoQueryResult
	results                           []autoQueryResult
	generation                        uint64
	nextAt, lastFailureCheck, retryAt time.Time
	lastSuccessAt                     time.Time
	failures                          int
	inFlight                          bool
	recoveryPossible                  bool
}

func (c *Client) autoQueryEnabled() bool { return c != nil && c.cfg.DNSQueryType == "AUTO" }

func (c *Client) autoDNSResponseOK(data []byte) bool {
	if !c.autoQueryEnabled() {
		return true
	}
	parsed, err := DnsParser.ParsePacketLite(data)
	return err == nil && parsed.Header.QR == 1 && parsed.Header.RCode == 0
}

func (c *Client) autoProbeTimeout() time.Duration {
	if c.autoQueryEnabled() && c.cfg.DNSAutoProbeTimeoutSeconds > 0 {
		return time.Duration(c.cfg.DNSAutoProbeTimeoutSeconds * float64(time.Second))
	}
	return c.mtuTestTimeout
}

func (c *Client) autoQueryTypes() []uint16 {
	var result []uint16
	for _, name := range c.cfg.DNSAutoQueryTypes {
		switch name {
		case "TXT":
			result = append(result, Enums.DNS_RECORD_TYPE_TXT)
		case "NS":
			result = append(result, Enums.DNS_RECORD_TYPE_NS)
		case "CNAME":
			result = append(result, Enums.DNS_RECORD_TYPE_CNAME)
		case "SRV":
			result = append(result, Enums.DNS_RECORD_TYPE_SRV)
		}
	}
	return result
}

func (c *Client) autoQueryUsable(r autoQueryResult) bool {
	return r.queryType != 0 && r.attempts > 0 && r.successes > 0 &&
		r.mtu.UploadBytes > 0 && r.mtu.DownloadBytes > 0 &&
		100*float64(r.successes)/float64(r.attempts) >= c.cfg.DNSAutoMinSuccessPercent
}

// A stable sort preserves the user-configured candidate order for exact ties.
func (c *Client) rankAutoQueryResults(results []autoQueryResult) []autoQueryResult {
	usable := make([]autoQueryResult, 0, len(results))
	for _, r := range results {
		if c.autoQueryUsable(r) {
			usable = append(usable, r)
		}
	}
	sort.SliceStable(usable, func(i, j int) bool {
		a, b := usable[i], usable[j]
		if a.successes*b.attempts != b.successes*a.attempts {
			return a.successes*b.attempts > b.successes*a.attempts
		}
		return a.speed() > b.speed()
	})
	return usable
}

func (c *Client) autoQueryImproves(candidate, current autoQueryResult) bool {
	if !c.autoQueryUsable(candidate) {
		return false
	}
	if !c.autoQueryUsable(current) {
		return true
	}
	left, right := candidate.successes*current.attempts, current.successes*candidate.attempts
	if left != right {
		return left > right
	}
	return candidate.speed() > current.speed() && candidate.speed() >= current.speed()*(1+c.cfg.DNSAutoMinSpeedImprovementPercent/100)
}

func (c *Client) sampleAutoQueryType(ctx context.Context, conn Connection, mtu mtuConnectionProbeResult, count int) autoQueryResult {
	result := autoQueryResult{queryType: conn.TunnelQueryType, mtu: mtu, attempts: count}
	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		return result
	}
	defer transport.conn.Close()
	stop := context.AfterFunc(ctx, func() { transport.conn.Close() })
	defer stop()
	for i := 0; i < count && ctx.Err() == nil; i++ {
		up, upRTT, upErr := c.sendUploadMTUProbe(ctx, &conn, transport, mtu.UploadBytes, mtuProbeOptions{Quiet: true})
		down, downRTT, downErr := c.sendDownloadMTUProbe(ctx, &conn, transport, mtu.DownloadBytes, mtu.UploadBytes, mtuProbeOptions{Quiet: true})
		if up && down && upErr == nil && downErr == nil {
			result.successes++
			result.elapsed += maxDuration(time.Nanosecond, upRTT+downRTT)
		}
	}
	if result.successes > 0 {
		result.mtu.ResolveTime = result.elapsed / time.Duration(2*result.successes)
	}
	if c.log != nil {
		c.log.Debugf("AUTO probe: %s via %s type=%s success=%d/%d UP=%d DOWN=%d estimated=%.0f B/s", conn.Domain, conn.ResolverLabel, Enums.DNSRecordTypeName(result.queryType), result.successes, result.attempts, mtu.UploadBytes, mtu.DownloadBytes, result.speed())
	}
	return result
}

func (c *Client) evaluateAutoQueryTypes(ctx context.Context, conn Connection, full bool) []autoQueryResult {
	var results []autoQueryResult
	for _, q := range c.autoQueryTypes() {
		if ctx.Err() != nil {
			break
		}
		candidate := conn
		candidate.TunnelQueryType = q
		mtu := mtuConnectionProbeResult{UploadBytes: c.syncedUploadMTU, UploadChars: c.syncedUploadChars, DownloadBytes: c.syncedDownloadMTU}
		if full {
			var reason mtuRejectReason
			mtu, reason = c.probeConnectionMTU(ctx, &candidate, c.maxUploadMTUPayload(conn.Domain))
			if reason != mtuRejectNone {
				results = append(results, autoQueryResult{queryType: q})
				continue
			}
		}
		results = append(results, c.sampleAutoQueryType(ctx, candidate, mtu, c.cfg.DNSAutoProbeCount))
	}
	return results
}

func (c *Client) discoverAutoQueryType(ctx context.Context, conn *Connection, _ int) (mtuConnectionProbeResult, mtuRejectReason) {
	results := c.evaluateAutoQueryTypes(ctx, *conn, true)
	ranked := c.rankAutoQueryResults(results)
	var best autoQueryResult
	if len(ranked) > 0 && ctx.Err() == nil {
		best = ranked[0]
	}
	c.autoQueryMu.Lock()
	if c.autoQueryStates == nil {
		c.autoQueryStates = make(map[string]*autoQueryState)
	}
	c.autoQueryGeneration++
	state := &autoQueryState{selected: best, results: results, generation: c.autoQueryGeneration, nextAt: c.nextAutoQueryCheck(conn.Key, c.now()), retryAt: c.now().Add(c.autoFailureCooldown())}
	c.autoQueryStates[conn.Key] = state
	conn.TunnelQueryType = best.queryType
	conn.QueryTypeGeneration = state.generation
	c.autoQueryMu.Unlock()
	if best.queryType == 0 {
		conn.IsValid = false
		return mtuConnectionProbeResult{}, mtuRejectUpload
	}
	c.logAutoQuerySelection(*conn, best, "initial selection")
	return best.mtu, mtuRejectNone
}

func (c *Client) nextAutoQueryCheck(key string, now time.Time) time.Time {
	interval := time.Duration(c.cfg.DNSAutoRecheckIntervalSeconds * float64(time.Second))
	spread := time.Duration(float64(interval) * c.cfg.DNSAutoRecheckJitterPercent / 100)
	if spread > 0 {
		hash := fnv.New64a()
		hash.Write([]byte(key))
		hash.Write([]byte(now.UTC().Format(time.RFC3339Nano)))
		interval += time.Duration(hash.Sum64()%uint64(2*spread+1)) - spread
	}
	return now.Add(interval)
}

func (c *Client) autoFailureCooldown() time.Duration {
	return time.Duration(c.cfg.DNSAutoFailureRecheckCooldownSeconds * float64(time.Second))
}

func (c *Client) noteAutoQueryOutcome(key string, queryType uint16, generation uint64, success bool, now time.Time) {
	if !c.autoQueryEnabled() || generation == 0 {
		return
	}
	c.autoQueryMu.Lock()
	defer c.autoQueryMu.Unlock()
	state := c.autoQueryStates[key]
	if state == nil || state.generation != generation || state.selected.queryType != queryType {
		return
	}
	if success {
		if !now.Before(state.lastSuccessAt) {
			state.lastSuccessAt = now
			state.failures = 0
		}
		return
	}
	if !now.After(state.lastSuccessAt) {
		return
	}
	state.failures++
}

// Called by the health loop. Each worker owns one path, and is included in the
// runtime wait group so all I/O stops before session MTU values are changed.
func (c *Client) runAutoQueryChecks(ctx context.Context, now time.Time) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil || c.runtimeResetPending.Load() {
		return
	}
	c.autoQueryMu.Lock()
	active := 0
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			active++
		}
	}
	type job struct {
		conn       Connection
		generation uint64
		priority   bool
		dueAt      time.Time
	}
	var jobs []job
	for key, s := range c.autoQueryStates {
		if s.inFlight {
			continue
		}
		conn, ok := c.GetConnectionByKey(key)
		if !ok {
			continue
		}
		failureDue := c.cfg.DNSAutoFailureRecheckEnabled && !now.Before(s.lastFailureCheck.Add(c.autoFailureCooldown())) &&
			(s.failures >= c.cfg.DNSAutoFailureThreshold || (!conn.IsValid && !now.Before(s.retryAt)))
		periodicDue := c.cfg.DNSAutoRecheckEnabled && !now.Before(s.nextAt)
		if failureDue || periodicDue {
			dueAt := s.nextAt
			if failureDue {
				dueAt = s.lastFailureCheck.Add(c.autoFailureCooldown())
				if !conn.IsValid && s.retryAt.After(dueAt) {
					dueAt = s.retryAt
				}
			}
			jobs = append(jobs, job{conn, s.generation, failureDue, dueAt})
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].priority != jobs[j].priority {
			return jobs[i].priority
		}
		if !jobs[i].dueAt.Equal(jobs[j].dueAt) {
			return jobs[i].dueAt.Before(jobs[j].dueAt)
		}
		return jobs[i].conn.Key < jobs[j].conn.Key
	})
	for _, j := range jobs {
		if active >= c.cfg.DNSAutoRecheckParallelism {
			break
		}
		s := c.autoQueryStates[j.conn.Key]
		s.inFlight = true
		if j.priority {
			s.lastFailureCheck = now
			s.failures = 0
		}
		active++
		c.asyncWG.Add(1)
		go func(j job) { defer c.asyncWG.Done(); c.checkAutoQueryPath(ctx, j.conn, j.generation) }(j)
	}
	c.autoQueryMu.Unlock()
}

func (c *Client) checkAutoQueryPath(ctx context.Context, conn Connection, generation uint64) {
	results := c.evaluateAutoQueryTypes(ctx, conn, false)
	var incumbent autoQueryResult
	for _, r := range results {
		if r.queryType == conn.TunnelQueryType {
			incumbent = r
			break
		}
	}
	ranked := c.rankAutoQueryResults(results)
	best := incumbent
	for _, candidate := range ranked {
		if candidate.queryType == conn.TunnelQueryType {
			best = candidate
			break
		}
		if conn.IsValid && !c.autoQueryImproves(candidate, incumbent) {
			best = incumbent
			break
		}
		if c.cfg.DNSAutoSwitchConfirmationCount > 0 {
			probeConn := conn
			probeConn.TunnelQueryType = candidate.queryType
			candidate = c.sampleAutoQueryType(ctx, probeConn, candidate.mtu, c.cfg.DNSAutoSwitchConfirmationCount)
			if !c.autoQueryUsable(candidate) || (conn.IsValid && !c.autoQueryImproves(candidate, incumbent)) {
				continue
			}
		}
		best = candidate
		break
	}
	usable := c.autoQueryUsable(best)
	recovery := false
	if !usable && ctx.Err() == nil {
		// This is the only publication needed to make the path unavailable.
		c.autoQueryMu.Lock()
		s := c.autoQueryStates[conn.Key]
		if s != nil && s.generation == generation && ctx.Err() == nil {
			invalid := conn
			invalid.IsValid = false
			c.balancer.SetConnectionTransport(invalid)
		}
		c.autoQueryMu.Unlock()
		if c.cfg.DNSAutoAllowMTURestart && c.balancer.ValidCount() == 0 {
			full := c.rankAutoQueryResults(c.evaluateAutoQueryTypes(ctx, conn, true))
			for _, r := range full {
				if r.mtu.UploadBytes < c.syncedUploadMTU || r.mtu.DownloadBytes < c.syncedDownloadMTU {
					recovery = true
					continue
				}
				// A smaller, more reliable candidate can rank first. Before
				// restarting, try every candidate able to carry the current MTU.
				probeConn := conn
				probeConn.TunnelQueryType = r.queryType
				best = c.sampleAutoQueryType(ctx, probeConn, mtuConnectionProbeResult{UploadBytes: c.syncedUploadMTU, UploadChars: c.syncedUploadChars, DownloadBytes: c.syncedDownloadMTU}, c.cfg.DNSAutoProbeCount)
				if c.autoQueryUsable(best) {
					usable = true
					recovery = false
					break
				}
			}
		}
	}
	c.autoQueryMu.Lock()
	defer c.autoQueryMu.Unlock()
	s := c.autoQueryStates[conn.Key]
	if s == nil || s.generation != generation {
		return
	}
	s.inFlight = false
	if ctx.Err() != nil {
		return
	}
	s.nextAt = c.nextAutoQueryCheck(conn.Key, c.now())
	s.retryAt = c.now().Add(maxDuration(time.Second, c.autoFailureCooldown()))
	s.results = results
	s.recoveryPossible = recovery
	if usable {
		current, exists := c.GetConnectionByKey(conn.Key)
		changed := conn.TunnelQueryType != best.queryType || !conn.IsValid || (exists && !current.IsValid)
		if changed {
			c.autoQueryGeneration++
			s.generation = c.autoQueryGeneration
			s.failures = 0
		}
		s.selected = best
		conn.TunnelQueryType = best.queryType
		conn.QueryTypeGeneration = s.generation
		conn.IsValid = true
		// Keep session MTU fixed; capacities measured at startup must not leak
		// into a running session via background probing.
		conn.UploadMTUBytes = c.syncedUploadMTU
		conn.UploadMTUChars = c.syncedUploadChars
		conn.DownloadMTUBytes = c.syncedDownloadMTU
		conn.MTUResolveTime = best.mtu.ResolveTime
		c.balancer.SetConnectionTransport(conn)
		if changed {
			c.logAutoQuerySelection(conn, best, "validated switch/recovery")
		}
	}
	c.maybeRestartAutoMTULocked()
}

func (c *Client) maybeRestartAutoMTULocked() {
	if !c.cfg.DNSAutoAllowMTURestart || c.balancer.ValidCount() != 0 {
		return
	}
	recovery := false
	for _, s := range c.autoQueryStates {
		if s.inFlight {
			return
		}
		recovery = recovery || s.recoveryPossible
	}
	if recovery {
		c.autoMTURescanPending.Store(true)
		c.requestSessionRestart("AUTO verified a smaller working MTU; no path supports the current session MTU")
	}
}

// A watchdog/session restart stops the background health loop. If every path is
// unavailable, reconnect must keep probing without depending on that stopped
// loop. Use the current session MTU, including when smaller-MTU restarts are off.
func (c *Client) recheckAutoPathsForSession(ctx context.Context) {
	type job struct {
		conn       Connection
		generation uint64
	}
	c.autoQueryMu.Lock()
	jobs := make([]job, 0, len(c.autoQueryStates))
	for key, state := range c.autoQueryStates {
		if conn, ok := c.GetConnectionByKey(key); ok {
			state.inFlight = true
			jobs = append(jobs, job{conn, state.generation})
		}
	}
	c.autoQueryMu.Unlock()
	queue := make(chan job, len(jobs))
	for _, j := range jobs {
		queue <- j
	}
	close(queue)
	var workers sync.WaitGroup
	for i := 0; i < min(max(1, c.cfg.DNSAutoRecheckParallelism), len(jobs)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range queue {
				c.checkAutoQueryPath(ctx, j.conn, j.generation)
			}
		}()
	}
	workers.Wait()
}

func (c *Client) logAutoQuerySelection(conn Connection, result autoQueryResult, reason string) {
	if c.log != nil {
		c.log.Infof("AUTO %s: %s via %s type=%s success=%d/%d UP=%d DOWN=%d estimated=%.0f B/s", reason, conn.Domain, conn.ResolverLabel, Enums.DNSRecordTypeName(result.queryType), result.successes, result.attempts, result.mtu.UploadBytes, result.mtu.DownloadBytes, result.speed())
	}
}
