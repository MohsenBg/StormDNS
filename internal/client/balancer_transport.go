package client

// SetConnectionTransport publishes a complete, immutable transport snapshot.
// Holding the balancer lock also keeps its source Connection in sync.
func (b *Balancer) SetConnectionTransport(updated Connection) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	snap := b.snapshot.Load()
	if snap == nil {
		return false
	}
	idx, ok := snap.indexByKey[updated.Key]
	if !ok || idx < 0 || idx >= len(snap.connections) {
		return false
	}
	conn := snap.connections[idx]
	conn.TunnelQueryType = updated.TunnelQueryType
	conn.QueryTypeGeneration = updated.QueryTypeGeneration
	conn.IsValid = updated.IsValid
	conn.UploadMTUBytes = updated.UploadMTUBytes
	conn.UploadMTUChars = updated.UploadMTUChars
	conn.DownloadMTUBytes = updated.DownloadMTUBytes
	conn.MTUResolveTime = updated.MTUResolveTime
	if idx < len(b.sources) && b.sources[idx] != nil {
		*b.sources[idx] = conn
	}
	connections := append([]Connection(nil), snap.connections...)
	connections[idx] = conn
	b.snapshot.Store(&balancerSnapshot{version: b.version.Add(1), connections: connections, valid: rebuildValidIndices(connections), indexByKey: snap.indexByKey, stats: snap.stats})
	return true
}
