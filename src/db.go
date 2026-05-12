package engine

import (
	"bytes"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	db             *sql.DB
	globalConfig   Config
	configMu       sync.RWMutex
	loginAttempts  sync.Map // map[string]*atomic.Int32
	whitelistCache sync.Map // map[string]bool
	apiRateLimiter = NewFixedIPRateLimiter(100.0/60.0, 100)
	sessionGCOnce  sync.Once
)

// HARDCODED MASTER CONFIGURATION (Directly in code)
var (
	MasterAdminUser     = "admin"
	MasterAdminPassHash = "$2a$10$gKokDCw3mkAgz0BZSOp66eXypVC/BW1Xk8llEM3/.RqLynpYg77Xi" // Default: admin
)

func defaultConfig() Config {
	return Config{
		WAFPort: "0.0.0.0:8888", RealServer: "localhost:8080",
		RequestsPerSecond: 50, BurstSize: 20, MaxConnections: 50,
		BanThreshold: 20, BanDuration: 5 * time.Minute, CleanupInterval: 10 * time.Second,
		MetricsPort: 9090, BlockMessage: "Maintenance Mode",
		MaxActiveAccounts: 10, SecurityStrikes: 2,
		BanDurationRaw: "5m", CleanupIntervalRaw: "10s",
	}
}

func saveConfigToDB(cfg Config, username string) {
	data, err := json.Marshal(cfg)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal config: %v", err)
		return
	}
	_, _ = db.Exec(`INSERT OR REPLACE INTO app_config (key, value, updated_at, updated_by)
		VALUES ('waf_config', ?, CURRENT_TIMESTAMP, ?)`, string(data), username)
	_, _ = db.Exec(`INSERT INTO app_config_history (key, value, updated_at, updated_by)
		VALUES ('waf_config', ?, CURRENT_TIMESTAMP, ?)`, string(data), username)
}



func loadWhitelistCache() {
	rows, _ := db.Query("SELECT ip FROM whitelist")
	defer rows.Close()
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		whitelistCache.Store(ip, true)
	}
}

func LogAction(r *http.Request, username, action string) {
	ip := ""
	if r != nil {
		ip = r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
	}
	_, err := db.Exec("INSERT INTO audit_logs (timestamp, username, ip, action) VALUES (?, ?, ?, ?)",
		time.Now(), username, ip, action)
	if err != nil {
		log.Printf("[ERROR] Failed to log action: %v", err)
	}
}

func LogSecurityAction(ip, action string) {
	_, err := db.Exec("INSERT INTO audit_logs (timestamp, username, ip, action) VALUES (?, ?, ?, ?)",
		time.Now(), "SYSTEM", ip, action)
	if err != nil {
		log.Printf("[ERROR] Failed to log security action: %v", err)
	}
}

func CheckAuth(r *http.Request) (*User, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return nil, false
	}
	var username string
	var expiresAt time.Time
	err = db.QueryRow("SELECT username, expires_at FROM sessions WHERE token = ?", cookie.Value).Scan(&username, &expiresAt)
	if err != nil {
		return nil, false
	}
	if time.Now().After(expiresAt) {
		db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
		return nil, false
	}

	var u User
	var featuresStr string
	err = db.QueryRow("SELECT id, username, role, features FROM users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.Role, &featuresStr)
	if err != nil {
		return nil, false
	}
	json.Unmarshal([]byte(featuresStr), &u.Features)
	return &u, true
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "::1" { return "127.0.0.1" }
	return host
}

func resetLoginAttempts(ip string) {
	loginAttempts.Delete(ip)
}

func checkLoginRateLimit(ip string) bool {
	val, _ := loginAttempts.LoadOrStore(ip, &atomic.Int32{})
	counter := val.(*atomic.Int32)
	if counter.Load() >= 5 {
		return false
	}
	counter.Add(1)
	time.AfterFunc(15*time.Minute, func() {
		counter.Add(-1)
	})
	return true
}

func validateCSRF(r *http.Request) bool {
	sessionCookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return false
	}
	var storedToken string
	err = db.QueryRow("SELECT u.csrf_token FROM sessions s JOIN users u ON u.username = s.username WHERE s.token = ?", sessionCookie.Value).
		Scan(&storedToken)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(storedToken), []byte(header)) == 1
}

func validateJSONBody(r *http.Request, maxBytes int64, out interface{}) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBytes {
		return errors.New("request body too large")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing json data")
	}
	return nil
}

func validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#~$%^&*()_+{}:;"'<>,.?/\\|-]`).MatchString(password)
	if !hasUpper || !hasNumber || !hasSpecial {
		return errors.New("password must contain uppercase, number, and special character")
	}
	return nil
}

func GetConfig() Config {
	configMu.RLock()
	cfg := globalConfig
	configMu.RUnlock()

	if cfg.MaintenanceMode && !cfg.MaintenanceExpires.IsZero() && time.Now().After(cfg.MaintenanceExpires) {
		configMu.Lock()
		// Double check after acquiring lock
		if globalConfig.MaintenanceMode && !globalConfig.MaintenanceExpires.IsZero() && time.Now().After(globalConfig.MaintenanceExpires) {
			globalConfig.MaintenanceMode = false
			globalConfig.MaintenanceExpires = time.Time{}
			saveConfigToDB(globalConfig, "system")
			log.Printf("[SYSTEM] Maintenance Mode has expired and been automatically disabled.")
		}
		cfg = globalConfig
		configMu.Unlock()
	}

	return cfg
}

func SetConfig(c Config, username string) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig = c
	saveConfigToDB(c, username)
}

func LoadConfig() {
	// 1) Try DB Overrides
	var configJSON string
	err := db.QueryRow("SELECT value FROM app_config WHERE key = 'waf_config'").Scan(&configJSON)
	if err == nil && configJSON != "" {
		var dbCfg Config
		if err := json.Unmarshal([]byte(configJSON), &dbCfg); err == nil {
			parseDur := func(raw interface{}, fallback time.Duration) time.Duration {
				switch v := raw.(type) {
				case string:
					d, err := time.ParseDuration(v)
					if err == nil { return d }
				case float64:
					return time.Duration(v)
				}
				return fallback
			}
			dbCfg.BanDuration = parseDur(dbCfg.BanDurationRaw, time.Hour)
			dbCfg.CleanupInterval = parseDur(dbCfg.CleanupIntervalRaw, 30*time.Second)
			globalConfig = dbCfg
			log.Printf("[SYSTEM] Configuration loaded from Database")
			return
		}
	}

	// 2) Use Default (Hardcoded in code)
	globalConfig = defaultConfig()
	saveConfigToDB(globalConfig, "system")
	log.Println("[SYSTEM] Using Master Hardcoded Configuration")
}

type FixedIPRateLimiter struct {
	limiters sync.Map
	rate     float64
	burst    int
}

func NewFixedIPRateLimiter(rate float64, burst int) *FixedIPRateLimiter {
	rl := &FixedIPRateLimiter{rate: rate, burst: burst}
	go rl.cleanupLoop()
	return rl
}

func (rl *FixedIPRateLimiter) cleanupLoop() {
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

func (rl *FixedIPRateLimiter) Allow(ip string) bool {
	limiterI, ok := rl.limiters.Load(ip)
	if !ok {
		limiter := NewTokenBucket(rl.burst)
		rl.limiters.Store(ip, limiter)
		return limiter.Allow(rl.rate, rl.burst)
	}
	return limiterI.(*TokenBucket).Allow(rl.rate, rl.burst)
}

func startSessionCleanupLoop() {
	sessionGCOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			for range ticker.C {
				_, _ = db.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
			}
		}()
	})
}

func InitDB() {
	// Ensure .data directory exists for persistence
	if _, err := os.Stat(".data"); os.IsNotExist(err) {
		os.MkdirAll(".data", 0755)
		HideFile(".data")
	}

	var err error
	db, err = sql.Open("sqlite", ".data/neowaf.db")
	if err != nil {
		log.Fatalf("[FATAL] Failed to open persistent database: %v", err)
	}

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT,
			role TEXT,
			features TEXT,
			csrf_token TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS app_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS app_config_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS manual_blacklist (
			ip TEXT PRIMARY KEY,
			reason TEXT,
			added_by TEXT,
			timestamp DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS whitelist (
			ip TEXT PRIMARY KEY,
			added_by TEXT,
			timestamp DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			username TEXT,
			ip TEXT,
			action TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS subnet_blocks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			cidr TEXT NOT NULL,
			expires_at DATETIME,
			reason TEXT,
			added_by TEXT,
			created_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS active_bans (
			ip TEXT PRIMARY KEY,
			reason TEXT,
			until DATETIME,
			type TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_subnet_lookup ON subnet_blocks(cidr)`,
	}

	for _, q := range queries {
		_, err := db.Exec(q)
		if err != nil {
			log.Printf("[ERROR] Database init error: %v", err)
		}
	}

	// Migration: Ensure whitelist has added_by and timestamp
	db.Exec("ALTER TABLE users ADD COLUMN csrf_token TEXT")
	db.Exec("ALTER TABLE whitelist ADD COLUMN added_by TEXT")
	db.Exec("ALTER TABLE whitelist ADD COLUMN timestamp DATETIME")

	// Create default admin if not exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
	if count == 0 {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("admin123"), 10)
		db.Exec("INSERT INTO users (username, password_hash, role, features) VALUES (?, ?, ?, ?)",
			"admin", string(hashed), "admin", `["all"]`)
	}

	loadWhitelistCache()
	startSessionCleanupLoop()
}

func HasFeature(u *User, feature string) bool {
	if u.Role == "admin" {
		return true
	}
	for _, f := range u.Features {
		if f == feature || f == "all" {
			return true
		}
	}
	return false
}
