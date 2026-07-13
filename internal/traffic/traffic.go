// Package traffic computes per-key uplink/downlink byte deltas from cumulative
// kernel counters. The collector remembers the last cumulative value seen for
// each key and returns the increment, treating any decrease (counter reset on
// kernel restart) as a fresh baseline.
package traffic

import (
	"strings"
	"sync"
)

// counter tracks last-seen cumulative totals for delta computation.
type counter struct {
	uplink   int64
	downlink int64
}

// Collector computes per-key traffic deltas. It is safe for concurrent use.
type Collector struct {
	mu   sync.Mutex
	last map[string]counter
}

// New returns an empty Collector.
func New() *Collector {
	return &Collector{last: make(map[string]counter)}
}

// Delta records new cumulative totals for key and returns the increment since
// the previous call. A decrease is treated as a counter reset (the new total
// becomes the delta and the baseline).
func (c *Collector) Delta(key string, up, down int64) (int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.last[key]
	dUp := up - prev.uplink
	dDown := down - prev.downlink
	if dUp < 0 {
		dUp = up
	}
	if dDown < 0 {
		dDown = down
	}
	c.last[key] = counter{uplink: up, downlink: down}
	return dUp, dDown
}

// NodeKey is the delta key for a node's aggregate inbound traffic.
func NodeKey(tag string) string { return "node>>>" + tag }

// UserKey is the delta key for a single user's traffic on a node.
func UserKey(tag, email string) string { return tag + ">>>user>>>" + email }

// Forget drops all tracking state associated with a node tag (its node counter
// and every per-user counter), called when a node is removed.
func (c *Collector) Forget(tag string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.last, NodeKey(tag))
	prefix := tag + ">>>user>>>"
	for k := range c.last {
		if strings.HasPrefix(k, prefix) {
			delete(c.last, k)
		}
	}
}
