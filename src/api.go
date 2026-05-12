package engine

import (
	"crypto/rand"
	_ "embed"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/disk"
)

//go:embed web/index.html
var indexHTML []byte

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if !validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return false
	}
	return true
}

func requireAPIRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if apiRateLimiter.Allow(getClientIP(r)) {
		return true
	}
	http.Error(w, "Too many API requests", http.StatusTooManyRequests)
	return false
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func (waf *DDoSProtectionWAF) registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { return }
		ip := getClientIP(r)
		if !checkLoginRateLimit(ip) {
			time.Sleep(5 * time.Second)
			LogSecurityAction(ip, "Rate limited login attempts")
			http.Error(w, "Too many attempts", http.StatusTooManyRequests)
			return
		}
		var req struct { Username, Password string }
		if err := validateJSONBody(r, 1<<20, &req); err != nil {
			http.Error(w, "Bad request body", http.StatusBadRequest)
			return
		}

		handleSuccess := func(user User) {
			token, _ := generateRandomHex(32)
			csrfToken, _ := generateRandomHex(32)
			expires := time.Now().Add(24 * time.Hour)
			db.Exec("DELETE FROM sessions WHERE username = ?", user.Username)
			_, _ = db.Exec("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)", token, user.Username, expires)
			_, _ = db.Exec("UPDATE users SET csrf_token = ? WHERE username = ?", csrfToken, user.Username)
			resetLoginAttempts(ip)
			LogAction(r, user.Username, "Logged in successfully")
			http.SetCookie(w, &http.Cookie{Name: "session_token", Value: token, Expires: expires, HttpOnly: true, Path: "/", SameSite: http.SameSiteStrictMode})
			http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Expires: expires, HttpOnly: false, Path: "/", SameSite: http.SameSiteStrictMode})
			w.WriteHeader(http.StatusOK)
		}

		// 1. Check Master Admin (Hardcoded)
		if req.Username == MasterAdminUser && bcrypt.CompareHashAndPassword([]byte(MasterAdminPassHash), []byte(req.Password)) == nil {
			handleSuccess(User{Username: MasterAdminUser, Role: "admin", Features: []string{"all"}})
			return
		}

		// 2. Check Database Users
		var foundUser User
		var featJSON string
		err := db.QueryRow("SELECT id, username, password_hash, role, features FROM users WHERE username = ?", req.Username).
			Scan(&foundUser.ID, &foundUser.Username, &foundUser.PasswordHash, &foundUser.Role, &featJSON)
		if err == nil {
			json.Unmarshal([]byte(featJSON), &foundUser.Features)
			if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(req.Password)); err == nil {
				handleSuccess(foundUser)
				return
			}
		}
		LogSecurityAction(ip, "Failed login attempt for username: "+req.Username)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { return }
		if !requireCSRF(w, r) { return }
		cookie, err := r.Cookie("session_token")
		if err == nil { db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value) }
		http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Expires: time.Now().Add(-1 * time.Hour), HttpOnly: true, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Expires: time.Now().Add(-1 * time.Hour), HttpOnly: false, Path: "/"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r)
		if !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"username": user.Username, "role": user.Role, "features": user.Features})
	})
	mux.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CheckAuth(r); !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
		cachedMetrics.RLock()
		defer cachedMetrics.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"waf_enabled": WafEnabled.Load(), "total_requests": waf.Stats.TotalRequests.Load(),
			"blocked_requests": waf.Stats.BlockedRequests.Load(), "active_connections": waf.Stats.ActiveConnections.Load(),
			"total_bans": waf.Stats.TotalBans.Load(), "rate_limit_hits": waf.Stats.RateLimitHits.Load(),
			"connection_limit_hits": waf.Stats.ConnectionLimitHits.Load(),
			"sqli_hits": waf.Stats.SQLiHits.Load(),
			"xss_hits": waf.Stats.XSSHits.Load(),
			"traversal_hits": waf.Stats.TraversalHits.Load(),
			"ssrf_hits": waf.Stats.SSRFHits.Load(),
			"protocol_hits": waf.Stats.ProtocolHits.Load(),
			"bruteforce_hits": waf.Stats.BruteforceHits.Load(),
			"sys_cpu": cachedMetrics.cpu,
			"sys_ram": cachedMetrics.ram,
			"sys_ram_total": cachedMetrics.ramTot,
			"sys_disk_speed": cachedMetrics.disk,
			"waf_rps": cachedMetrics.rps,
			"waf_active_bans": cachedMetrics.activeBans,
			"sys_uptime": time.Since(StartTime).Round(time.Second).String(),
		})
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r)
		if !ok || user.Role != "admin" { http.Error(w, "Unauthorized", http.StatusForbidden); return }
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if r.Method == http.MethodGet {
			rows, _ := db.Query("SELECT id, username, role, features FROM users")
			defer rows.Close()
			var users []User
			for rows.Next() {
				var u User; var f string; rows.Scan(&u.ID, &u.Username, &u.Role, &f); json.Unmarshal([]byte(f), &u.Features); users = append(users, u)
			}
			w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(users); return
		}
		if r.Method == http.MethodPost {
			var n struct { Username, Password, Role string; Features []string }
			if err := validateJSONBody(r, 1<<20, &n); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			
			if n.Role == "" { n.Role = "subuser" }
			if err := validatePasswordStrength(n.Password); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest); return
			}
			
			// Enforce MaxActiveAccounts only for subusers
			if n.Role == "subuser" {
				var count int
				db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'subuser'").Scan(&count)
				if count >= GetConfig().MaxActiveAccounts {
					http.Error(w, "Maximum active accounts reached", http.StatusBadRequest)
					return
				}
			}

			hashed, _ := bcrypt.GenerateFromPassword([]byte(n.Password), 10)
			f, _ := json.Marshal(n.Features)
			_, err := db.Exec("INSERT INTO users (username, password_hash, role, features) VALUES (?, ?, ?, ?)", n.Username, string(hashed), n.Role, string(f))
			if err != nil { http.Error(w, "Exists", http.StatusBadRequest); return }
			LogAction(r, user.Username, "Created "+n.Role+": "+n.Username); w.WriteHeader(http.StatusCreated); return
		}
		if r.Method == http.MethodDelete {
			var req struct { Username string }
			if err := validateJSONBody(r, 1<<20, &req); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			if req.Username == "admin" { return }
			db.Exec("DELETE FROM users WHERE username = ?", req.Username)
			LogAction(r, user.Username, "Deleted user: "+req.Username); w.WriteHeader(http.StatusOK); return
		}
		if r.Method == http.MethodPut { // Update sub-user password or features
			var req struct { Username, Password string; Features []string }
			if err := validateJSONBody(r, 1<<20, &req); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			if req.Username == "admin" { return }
			
			if req.Password != "" {
				if err := validatePasswordStrength(req.Password); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest); return
				}
				hashed, _ := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
				db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(hashed), req.Username)
				LogAction(r, user.Username, "Changed password for user: "+req.Username)
			}
			
			if req.Features != nil {
				f, _ := json.Marshal(req.Features)
				db.Exec("UPDATE users SET features = ? WHERE username = ?", string(f), req.Username)
				LogAction(r, user.Username, "Updated permissions for user: "+req.Username)
			}
			
			w.WriteHeader(http.StatusOK); return
		}
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r); if !ok { http.Error(w, "Unauthorized", http.StatusUnauthorized); return }
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json"); cfg := GetConfig(); cfg.AdminPasswordHash = ""; json.NewEncoder(w).Encode(cfg); return
		}
		if r.Method == http.MethodPost {
			var update map[string]interface{}
			if err := validateJSONBody(r, 1<<20, &update); err != nil {
				http.Error(w, err.Error(), 400); return
			}

			// 1. Handle Self-Password Update (Always Allowed for Authenticated Users)
			if adminPass, ok := update["admin_password"].(string); ok && adminPass != "" {
				if err := validatePasswordStrength(adminPass); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest); return
				}
				h, _ := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
				db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(h), user.Username)
				if len(update) == 1 {
					LogAction(r, user.Username, "Updated Account Password")
					w.WriteHeader(http.StatusOK); return
				}
			}

			// 2. Enforce waf_config permission for other settings
			if !HasFeature(user, "waf_config") {
				http.Error(w, "Forbidden: Insufficient Permissions (waf_config required)", http.StatusForbidden)
				return
			}

			cfg := GetConfig()
			oldPort := cfg.MetricsPort
			if v, ok := update["metrics_port"].(float64); ok { cfg.MetricsPort = int(v) }
			oldWafPort := cfg.WAFPort
			if v, ok := update["waf_port"].(string); ok { cfg.WAFPort = v }
			if v, ok := update["real_server"].(string); ok { cfg.RealServer = v }
			if v, ok := update["requests_per_second"].(float64); ok { cfg.RequestsPerSecond = v }
			if v, ok := update["burst_size"].(float64); ok { cfg.BurstSize = int(v) }
			if v, ok := update["max_connections"].(float64); ok { cfg.MaxConnections = int32(v) }
			if v, ok := update["ban_threshold"].(float64); ok { cfg.BanThreshold = int(v) }
			if v, ok := update["max_active_accounts"].(float64); ok { cfg.MaxActiveAccounts = int(v) }
			if v, ok := update["security_strikes"].(float64); ok { cfg.SecurityStrikes = int(v) }
			if v, ok := update["block_message"].(string); ok { cfg.BlockMessage = v }
			if v, ok := update["auto_unban"].(bool); ok { cfg.AutoUnban = v }
			if v, ok := update["auto_unban_hours"].(float64); ok { cfg.AutoUnbanHours = int(v) }

			if v, ok := update["ban_duration"].(string); ok {
				if d, err := time.ParseDuration(v); err == nil {
					cfg.BanDuration = d
					cfg.BanDurationRaw = v
				}
			}
			if v, ok := update["cleanup_interval"].(string); ok {
				if d, err := time.ParseDuration(v); err == nil {
					cfg.CleanupInterval = d
					cfg.CleanupIntervalRaw = v
				}
			}

			oldMaint := cfg.MaintenanceMode
			if v, ok := update["maintenance_mode"].(bool); ok { cfg.MaintenanceMode = v }
			if v, ok := update["maintenance_expires"].(string); ok {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					cfg.MaintenanceExpires = t
				}
			}

			SetConfig(cfg, user.Username)
			if oldMaint != cfg.MaintenanceMode {
				waf.FlushConnections()
			}
			LogAction(r, user.Username, "Updated WAF Configuration")

			// Auto-Restart WAF if port changed
			if oldWafPort != cfg.WAFPort {
				log.Printf("[SYSTEM] WAF Port changed from %s to %s. Triggering auto-restart...", oldWafPort, cfg.WAFPort)
				waf.Restart()
			}
			if oldPort != cfg.MetricsPort {
				log.Printf("[SYSTEM] Metrics port changed from %d to %d. Restarting dashboard server...", oldPort, cfg.MetricsPort)
				oldSrv := waf.MetricsServer
				go func(srv *http.Server) {
					if srv != nil {
						time.Sleep(500 * time.Millisecond)
						srv.Close()
					}
				}(oldSrv)
			}
			w.WriteHeader(200); return
		}
	})

	mux.HandleFunc("/api/config/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { return }
		user, ok := CheckAuth(r)
		if !ok || !HasFeature(user, "waf_config") {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		defaultCfg := defaultConfig()
		SetConfig(defaultCfg, user.Username)
		LogAction(r, user.Username, "Reset configuration to defaults")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "reset to defaults"})
	})

	mux.HandleFunc("/api/config/export", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r)
		if !ok || !HasFeature(user, "waf_config") {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		if !requireAPIRateLimit(w, r) { return }
		cfg := GetConfig()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=neowaf-backup.json")
		json.NewEncoder(w).Encode(cfg)
		LogAction(r, user.Username, "Exported configuration")
	})

	mux.HandleFunc("/api/config/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { return }
		user, ok := CheckAuth(r)
		if !ok || !HasFeature(user, "waf_config") {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		var imported Config
		if err := validateJSONBody(r, 1<<20, &imported); err != nil {
			http.Error(w, "Invalid config file", http.StatusBadRequest)
			return
		}
		SetConfig(imported, user.Username)
		LogAction(r, user.Username, "Imported configuration from file")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "imported successfully"})
	})

	mux.HandleFunc("/api/config/history", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r)
		if !ok || user.Role != "admin" {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		if !requireAPIRateLimit(w, r) { return }
		rows, err := db.Query(`
			SELECT updated_at, updated_by
			FROM app_config_history
			WHERE key = 'waf_config'
			ORDER BY updated_at DESC
			LIMIT 50
		`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		var history []map[string]interface{}
		for rows.Next() {
			var updatedAt time.Time
			var updatedBy sql.NullString
			_ = rows.Scan(&updatedAt, &updatedBy)
			history = append(history, map[string]interface{}{
				"timestamp":   updatedAt,
				"modified_by": updatedBy.String,
			})
		}
		if history == nil {
			history = []map[string]interface{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(history)
	})
	mux.HandleFunc("/api/security/unban", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r); if !ok { return }
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if !HasFeature(user, "security_hub") { http.Error(w, "Forbidden", http.StatusForbidden); return }
		
		var req struct { IP string `json:"ip"` }
		if err := validateJSONBody(r, 1<<20, &req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest); return
		}

		ip := req.IP
		// 1. Database Wipe
		db.Exec("DELETE FROM manual_blacklist WHERE ip = ?", ip)
		db.Exec("DELETE FROM manual_blacklist WHERE ip = '127.0.0.1'") // Safety for localhost
		db.Exec("DELETE FROM whitelist WHERE ip = ?", ip)
		db.Exec("DELETE FROM whitelist WHERE ip = '127.0.0.1'")
		
		// 2. Memory Wipe
		waf.BanManager.bans.Delete(ip)
		waf.BanManager.bans.Delete("127.0.0.1")
		waf.BanManager.violations.Delete(ip)
		waf.BanManager.violations.Delete("127.0.0.1")
		whitelistCache.Delete(ip)
		whitelistCache.Delete("127.0.0.1")

		LogAction(r, user.Username, "Global Unban: "+ip)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/bans", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r); if !ok { return }
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if r.Method == http.MethodGet {
			var bans []map[string]interface{}
			waf.BanManager.bans.Range(func(k, v interface{}) bool {
				b := v.(*BanInfo)
				if time.Now().Before(b.Until) {
					bans = append(bans, map[string]interface{}{"ip": k.(string), "reason": b.Reason, "until": b.Until, "type": "Auto"})
				} else {
					waf.BanManager.bans.Delete(k)
				}
				return true
			})
			rows, _ := db.Query("SELECT ip, reason FROM manual_blacklist")
			defer rows.Close()
			for rows.Next() {
				var ip, reason string; rows.Scan(&ip, &reason)
				bans = append(bans, map[string]interface{}{"ip": ip, "reason": reason, "until": "Permanent", "type": "Manual"})
			}
			if bans == nil { bans = []map[string]interface{}{} }
			w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(bans); return
		}
		if r.Method == http.MethodPost {
			if !HasFeature(user, "security_hub") {
				http.Error(w, "Forbidden", http.StatusForbidden); return
			}
			var n struct { IP string `json:"ip"`; Reason string `json:"reason"`; Action string `json:"action"` }
			if err := validateJSONBody(r, 1<<20, &n); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			if n.Action == "blacklist" || n.Action == "whitelist" {
				if net.ParseIP(n.IP) == nil {
					http.Error(w, "Invalid IP address", http.StatusBadRequest); return
				}
			}
			if n.Action == "blacklist" {
				db.Exec("INSERT OR REPLACE INTO manual_blacklist (ip, reason, added_by, timestamp) VALUES (?, ?, ?, ?)", n.IP, n.Reason, user.Username, time.Now())
				LogAction(r, user.Username, "Manual Blacklist: "+n.IP)
			} else if n.Action == "whitelist" {
				db.Exec("INSERT OR REPLACE INTO whitelist (ip, added_by, timestamp) VALUES (?, ?, ?)", n.IP, user.Username, time.Now()); whitelistCache.Store(n.IP, true)
				LogAction(r, user.Username, "Manual Whitelist: "+n.IP)
			}
			w.WriteHeader(http.StatusOK); return
		}
	})
	mux.HandleFunc("/api/whitelist", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CheckAuth(r); !ok { return }
		rows, _ := db.Query("SELECT ip, added_by, timestamp FROM whitelist")
		defer rows.Close()
		var list []map[string]interface{}
		for rows.Next() {
			var ip string
			var addedBy sql.NullString
			var t sql.NullTime
			rows.Scan(&ip, &addedBy, &t)
			
			author := "Admin"
			if addedBy.Valid && addedBy.String != "" {
				author = addedBy.String
			}
			
			list = append(list, map[string]interface{}{
				"ip": ip, 
				"added_by": author, 
				"timestamp": t.Time,
			})
		}
		if list == nil { list = []map[string]interface{}{} }
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CheckAuth(r); !ok { return }
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(map[string]interface{}{"logs": SysLogs.GetLogs()})
	})
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r); if !ok || r.Method != http.MethodPost { return }
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if !HasFeature(user, "waf_control") { return }
		var req struct { Command string }
		if err := validateJSONBody(r, 1<<20, &req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest); return
		}
		switch req.Command {
		case "enable": WafEnabled.Store(true); LogAction(r, user.Username, "Enabled WAF")
		case "disable": WafEnabled.Store(false); LogAction(r, user.Username, "Disabled WAF")
		case "restart_waf": LogAction(r, user.Username, "Restarted WAF"); waf.Restart()
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r); if !ok { return }
		
		var rows *sql.Rows
		var err error
		if user.Role == "admin" {
			rows, err = db.Query("SELECT timestamp, username, ip, action FROM audit_logs ORDER BY timestamp DESC LIMIT 500")
		} else {
			// Sub-users see ONLY their own logs + SYSTEM security blocks
			rows, err = db.Query("SELECT timestamp, username, ip, action FROM audit_logs WHERE username = ? OR username = 'SYSTEM' ORDER BY timestamp DESC LIMIT 500", user.Username)
		}
		
		if err != nil { http.Error(w, err.Error(), 500); return }
		defer rows.Close()
		var logs []AuditLog
		for rows.Next() {
			var l AuditLog; rows.Scan(&l.Time, &l.Username, &l.IP, &l.Action); logs = append(logs, l)
		}
		if logs == nil { logs = []AuditLog{} }
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(logs)
	})
	mux.HandleFunc("/api/subnet/block", func(w http.ResponseWriter, r *http.Request) {
		user, ok := CheckAuth(r)
		if !ok || !HasFeature(user, "waf_control") {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		if !requireAPIRateLimit(w, r) { return }
		if !requireCSRF(w, r) { return }
		if r.Method == http.MethodPost {
			var n struct { CIDR string `json:"cidr"`; Reason string `json:"reason"`; DurationHours int }
			if err := validateJSONBody(r, 1<<20, &n); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			var expiresAt *time.Time
			if n.DurationHours > 0 {
				t := time.Now().Add(time.Duration(n.DurationHours) * time.Hour)
				expiresAt = &t
			}
			_, err := db.Exec("INSERT INTO subnet_blocks (cidr, expires_at, reason, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
				n.CIDR, expiresAt, n.Reason, user.Username, time.Now())
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			waf.SubnetBlocker.LoadFromDB()
			LogAction(r, user.Username, "Added Subnet Block: "+n.CIDR)
			w.WriteHeader(http.StatusCreated)
		} else if r.Method == http.MethodDelete {
			var req struct { CIDR string `json:"cidr"` }
			if err := validateJSONBody(r, 1<<20, &req); err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest); return
			}
			db.Exec("DELETE FROM subnet_blocks WHERE cidr = ?", req.CIDR)
			waf.SubnetBlocker.LoadFromDB()
			LogAction(r, user.Username, "Removed Subnet Block: "+req.CIDR)
			w.WriteHeader(http.StatusOK)
		}
	})
	mux.HandleFunc("/api/subnet/blocks", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := CheckAuth(r); !ok { return }
		rows, _ := db.Query("SELECT cidr, expires_at, reason, added_by, created_at FROM subnet_blocks")
		defer rows.Close()
		var list []map[string]interface{}
		for rows.Next() {
			var cidr, reason, addedBy string; var expiresAt *time.Time; var createdAt time.Time
			rows.Scan(&cidr, &expiresAt, &reason, &addedBy, &createdAt)
			list = append(list, map[string]interface{}{
				"cidr": cidr, "expires_at": expiresAt, "reason": reason, "added_by": addedBy, "created_at": createdAt,
			})
		}
		if list == nil { list = []map[string]interface{}{} }
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(list)
	})
}

func (waf *DDoSProtectionWAF) StartMetricsServer() {
	for {
		cfg := GetConfig()
		mux := http.NewServeMux()
		waf.registerHandlers(mux)

		// The Metrics/Management server should be accessible even if IP is banned
		// because that's where the Unban action happens.
		waf.MetricsServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.MetricsPort),
			Handler: withSecurityHeaders(mux),
		}
		log.Printf("[SYSTEM] Metrics Dashboard starting on :%d", cfg.MetricsPort)
		err := waf.MetricsServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Metrics server error: %v. Retrying in 5s...", err)
			time.Sleep(5 * time.Second)
		} else if err == http.ErrServerClosed {
			log.Printf("[SYSTEM] Metrics server closed for restart.")
			time.Sleep(1 * time.Second)
		}
	}
}

func CollectMetricsLoop(waf *DDoSProtectionWAF) {
	dStats, _ := disk.IOCounters()
	for _, s := range dStats { lastDiskRead += s.ReadBytes; lastDiskWrite += s.WriteBytes }
	lastTickTime = time.Now()
	var lastTotalRequests int64
	if waf != nil { lastTotalRequests = waf.Stats.TotalRequests.Load() }
	for {
		time.Sleep(1 * time.Second)
		now := time.Now()
		elapsed := now.Sub(lastTickTime).Seconds()
		if elapsed <= 0 { elapsed = 1 }
		cpuUsage, _ := cpu.Percent(0, false)
		vm, _ := mem.VirtualMemory()
		dStats, _ := disk.IOCounters()
		cachedMetrics.Lock()
		if len(cpuUsage) > 0 { cachedMetrics.cpu = fmt.Sprintf("%.1f%%", cpuUsage[0]) }
		cachedMetrics.ram = fmt.Sprintf("%d MB", vm.Used/1024/1024)
		cachedMetrics.ramTot = vm.Total / 1024 / 1024
		var currentRead, currentWrite uint64
		for _, s := range dStats { currentRead += s.ReadBytes; currentWrite += s.WriteBytes }
		if currentRead >= lastDiskRead && currentWrite >= lastDiskWrite {
			diff := (currentRead - lastDiskRead) + (currentWrite - lastDiskWrite)
			speed := float64(diff) / 1024 / 1024 / elapsed
			if speed < 5000 { cachedMetrics.disk = fmt.Sprintf("%.2f MB/s", speed) }
		}
		lastDiskRead, lastDiskWrite = currentRead, currentWrite
		if waf != nil {
			currRequests := waf.Stats.TotalRequests.Load()
			rps := float64(currRequests-lastTotalRequests) / elapsed
			cachedMetrics.rps = fmt.Sprintf("%.2f RPS", rps)
			lastTotalRequests = currRequests
			count := 0
			waf.BanManager.bans.Range(func(_, _ interface{}) bool { count++; return true })
			cachedMetrics.activeBans = count
		}
		lastTickTime = now
		cachedMetrics.Unlock()
	}
}
