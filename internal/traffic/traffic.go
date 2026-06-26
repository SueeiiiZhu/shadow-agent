// Package traffic reports per-node uplink/downlink byte deltas. Where an Xray
// stats API is reachable the real counters would be queried; in environments
// without a running kernel it returns zero deltas. The collector tracks the
// last reported cumulative value per tag and returns the increment.
package traffic

import "sync"

// Stat is a single node's traffic delta since the previous collection.
type Stat struct {
	Tag           string `json:"tag"`
	UplinkBytes   int64  `json:"uplinkBytes"`
	DownlinkBytes int64  `json:"downlinkBytes"`
}

// counter tracks last-seen cumulative totals for delta computation.
type counter struct {
	uplink   int64
	downlink int64
}

// Collector computes per-tag traffic deltas. It is safe for concurrent use.
type Collector struct {
	mu   sync.Mutex
	last map[string]counter
}

// New returns an empty Collector.
func New() *Collector {
	return &Collector{last: make(map[string]counter)}
}

// Sampler supplies cumulative uplink/downlink totals for a tag. When no kernel
// stats source is available it should return (0, 0, false).
type Sampler func(tag string) (uplink, downlink int64, ok bool)

// Collect returns the byte delta for each tag since the previous call. When the
// sampler reports no data the delta is zero. Tags are typically the active node
// tags supplied by the caller.
func (c *Collector) Collect(tags []string, sample Sampler) []Stat {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Stat, 0, len(tags))
	for _, tag := range tags {
		up, down, ok := int64(0), int64(0), false
		if sample != nil {
			up, down, ok = sample(tag)
		}
		if !ok {
			// No kernel/stats: report zero increment.
			out = append(out, Stat{Tag: tag})
			continue
		}

		prev := c.last[tag]
		dUp := up - prev.uplink
		dDown := down - prev.downlink
		if dUp < 0 {
			dUp = up // counter reset
		}
		if dDown < 0 {
			dDown = down
		}
		c.last[tag] = counter{uplink: up, downlink: down}
		out = append(out, Stat{Tag: tag, UplinkBytes: dUp, DownlinkBytes: dDown})
	}
	return out
}

// Forget drops tracking state for a removed tag.
func (c *Collector) Forget(tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.last, tag)
}
