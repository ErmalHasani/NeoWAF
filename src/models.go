package engine

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type IPConnLimiter struct {
	conns sync.Map // map[string]*atomic.Int32
}

func NewIPConnLimiter() *IPConnLimiter {
	return &IPConnLimiter{}
}

func (l *IPConnLimiter) Add(ip string) int32 {
	v, _ := l.conns.LoadOrStore(ip, &atomic.Int32{})
	return v.(*atomic.Int32).Add(1)
}

func (l *IPConnLimiter) Done(ip string) {
	v, ok := l.conns.Load(ip)
	if ok {
		v.(*atomic.Int32).Add(-1)
	}
}

func (l *IPConnLimiter) Get(ip string) int32 {
	v, ok := l.conns.Load(ip)
	if ok {
		return v.(*atomic.Int32).Load()
	}
	return 0
}

type SubnetBlocker struct {
	blocks []*net.IPNet
	mu     sync.RWMutex
}

func NewSubnetBlocker() *SubnetBlocker {
	return &SubnetBlocker{blocks: []*net.IPNet{}}
}

func (sb *SubnetBlocker) AddBlock(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.blocks = append(sb.blocks, ipnet)
	return nil
}

func (sb *SubnetBlocker) IsBlocked(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	for _, block := range sb.blocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func (sb *SubnetBlocker) LoadFromDB() {
	rows, err := db.Query("SELECT cidR FROM subnet_blocks WHERE expires_at IS NULL OR expires_at > ?", time.Now())
	if err != nil {
		return
	}
	defer rows.Close()
	
	newBlocks := []*net.IPNet{}
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err == nil {
			_, ipnet, _ := net.ParseCIDR(cidr)
			if ipnet != nil {
				newBlocks = append(newBlocks, ipnet)
			}
		}
	}
	sb.mu.Lock()
	sb.blocks = newBlocks
	sb.mu.Unlock()
}

type User struct {
	ID           int64    `json:"id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash,omitempty"`
	Role         string   `json:"role"`     // "admin" or "subuser"
	Features     []string `json:"features"` // "waf_control", "config_edit"
}

type Config struct {
	WAFPort           string        `json:"waf_port"`
	RealServer        string        `json:"real_server"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	MaxConnections    int32         `json:"max_connections"`
	BanThreshold      int           `json:"ban_threshold"`
	BanDuration       time.Duration `json:"-"`
	CleanupInterval   time.Duration `json:"-"`
	BanDurationRaw    interface{}   `json:"ban_duration"`
	CleanupIntervalRaw interface{}  `json:"cleanup_interval"`
	MetricsPort       int           `json:"metrics_port"`
	AdminUser         string        `json:"admin_user,omitempty"`
	AdminPasswordHash string        `json:"admin_password_hash,omitempty"`
	BlockMessage      string        `json:"block_message"`
	AutoUnban           bool    `json:"auto_unban"`
	AutoUnbanHours      int     `json:"auto_unban_hours"`
	MaintenanceMode     bool    `json:"maintenance_mode"`
	MaintenanceExpires  time.Time `json:"maintenance_expires"`
	MaxActiveAccounts   int       `json:"max_active_accounts"`
	SecurityStrikes     int       `json:"security_strikes"`
}

type SessionInfo struct {
	Expires  time.Time
	Username string
}

type AuditLog struct {
	Time     time.Time `json:"time"`
	Username string    `json:"username"`
	IP       string    `json:"ip"`
	Action   string    `json:"action"`
}

type LogBuffer struct {
	lines []string
	max   int
	mu    sync.Mutex
}

func NewLogBuffer(max int) *LogBuffer { return &LogBuffer{max: max} }
func (b *LogBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.lines) >= b.max { b.lines = b.lines[1:] }
	b.lines = append(b.lines, string(p))
	return len(p), nil
}
func (b *LogBuffer) GetLogs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	cpy := make([]string, len(b.lines))
	copy(cpy, b.lines)
	return cpy
}

type WAFStats struct {
	TotalRequests, BlockedRequests, ActiveConnections, TotalBans, RateLimitHits, ConnectionLimitHits atomic.Int64
	SQLiHits, XSSHits, TraversalHits, SSRFHits, ProtocolHits, BruteforceHits atomic.Int64
}

type TokenBucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
	mu         sync.Mutex
}

func NewTokenBucket(burst int) *TokenBucket {
	return &TokenBucket{tokens: float64(burst), lastRefill: time.Now(), lastSeen: time.Now()}
}

func (tb *TokenBucket) Allow(rate float64, burst int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.lastSeen = time.Now()
	maxTokens := float64(burst)
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * rate
	if tb.tokens > maxTokens { tb.tokens = maxTokens }
	tb.lastRefill = now
	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}
	return false
}

type IPRateLimiter struct {
	limiters sync.Map
}

func NewIPRateLimiter() *IPRateLimiter {
	rl := &IPRateLimiter{}
	go rl.cleanupLoop()
	return rl
}

func (rl *IPRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.limiters.Range(func(key, value interface{}) bool {
			limiter := value.(*TokenBucket)
			if time.Since(limiter.lastSeen) > 10*time.Minute {
				rl.limiters.Delete(key)
			}
			return true
		})
	}
}

func (rl *IPRateLimiter) Allow(ip string) bool {
	cfg := GetConfig()
	limiterI, ok := rl.limiters.Load(ip)
	if !ok {
		limiter := NewTokenBucket(cfg.BurstSize)
		rl.limiters.Store(ip, limiter)
		return limiter.Allow(cfg.RequestsPerSecond, cfg.BurstSize)
	}
	return limiterI.(*TokenBucket).Allow(cfg.RequestsPerSecond, cfg.BurstSize)
}

type BanInfo struct {
	Until  time.Time
	Reason string
}

type BanManager struct {
	bans, violations, StealthWarned sync.Map
	Stats           *WAFStats
	mu              sync.RWMutex
}

func NewBanManager(stats *WAFStats) *BanManager {
	bm := &BanManager{Stats: stats}
	go bm.cleanupLoop()
	return bm
}

func (bm *BanManager) LoadBansFromDB() {
	rows, err := db.Query("SELECT ip, reason, until FROM active_bans WHERE until > ?", time.Now())
	if err != nil {
		return
	}
	defer rows.Close()
	
	count := 0
	for rows.Next() {
		var ip, reason string
		var until time.Time
		if err := rows.Scan(&ip, &reason, &until); err == nil {
			bm.bans.Store(ip, &BanInfo{Until: until, Reason: reason})
			bm.Stats.TotalBans.Add(1)
			count++
		}
	}
	if count > 0 {
		log.Printf("[SYSTEM] Restored %d active bans from database", count)
	}
}
