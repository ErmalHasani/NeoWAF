package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

var (
	SysLogs      = NewLogBuffer(200)
	WafEnabled   atomic.Bool
	StartTime     = time.Now()
	
	lastDiskRead  uint64
	lastDiskWrite uint64
	lastTickTime  = time.Now()
	
	// Cached metrics for optimization
	cachedMetrics struct {
		sync.RWMutex
		cpu    string
		ram    string
		ramTot uint64
		disk   string
		rps    string // Requests Per Second
		activeBans int // Current active bans count
	}
)
