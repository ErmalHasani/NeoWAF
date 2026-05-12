package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"encoding/binary"
	"strconv"
)

const (
	MAX_DECODE_DEPTH = 5
)

var (
	// SSRF & Protocol Patterns
	ssrfPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(https?://)?(?:[0-9]+\.){3}[0-9]+`),
		regexp.MustCompile(`(?i)0[0-7]+\.[0-7]+\.[0-7]+\.[0-7]+`),
		regexp.MustCompile(`(?i)(?:https?://)?[a-f0-9]+\.(?:[0-9]+\.){3}[0-9]+\.nip\.io`),
		regexp.MustCompile(`(?i)@[a-z0-9\-]+\.[a-z]+/`),
		regexp.MustCompile(`(?i)127\.0\.0\.1|localhost|0\.0\.0\.0|127\.0\.0\.1`),
		regexp.MustCompile(`(?i)(169\.254\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)`),
	}
	
	// Specialized Traversal Patterns
	unicodeTraversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)%c0%ae|%c0%af|%c1%9c|%e0%40%ae|%e0%80%af`),
		regexp.MustCompile(`\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}`),
	}
	
	nestedTraversalPattern = regexp.MustCompile(`\.{2,}[/\\]\.{2,}`)
	zipSlipEnhanced        = regexp.MustCompile(`(?i)(\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e%5c)`)
	
	// DOM & Logic Patterns
	domPatterns = []string{
		`<form[^>]*name=`, `<input[^>]*name=`, `<img[^>]*name=`,
		`onload=`, `onerror=`, `onclick=`, `constructor`, `__proto__`, `prototype`,
	}
	
	methodOverrideHeaders = []string{
		"X-HTTP-Method-Override", "X-Method-Override", "X-Original-Method",
		"X-HTTP-Method", "X-Method", "X-Original-URL", "X-Rewrite-URL",
	}

	timeBasedPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(sleep|waitfor|delay|benchmark|pg_sleep)\s*\(`),
		regexp.MustCompile(`(?i)(\|\||&&|;)\s*(sleep|ping|timeout)\s+\d+`),
	}

	sensitiveFiles = []string{
		"/etc/passwd", "/etc/shadow", "/etc/hosts", "/windows/win.ini",
		"/windows/system.ini", "/boot.ini", "/web.config", "/.htaccess",
		"/proc/self/environ", "/proc/version",
	}

	sqlKeywords = []string{"select", "union", "insert", "update", "delete", "drop", "alter", "create"}

	// Pre-compiled regexes for performance
	pathNormalizer   = regexp.MustCompile(`/+`)
	unicodeDecoder   = regexp.MustCompile(`%u([0-9a-fA-F]{4})`)
	decimalIPRegex   = regexp.MustCompile(`\b[0-9]{8,10}\b`)
	sqliHeuristic    = regexp.MustCompile(`(?i)(['"][^'"]+['"]\s*=\s*['"][^'"]+['"]|\d+\s*=\s*\d+|true\s*=\s*true|or\s+1|union\s+select)`)
	xssHeuristic     = regexp.MustCompile(`(?i)<(script|iframe|svg|img|body)|\bon\w+\s*=|{{.*}}|\${.*}|7\*7`)
	bypassHeuristic  = regexp.MustCompile(`(?i)(config|self|class|mro|globals|request|render)`)
	sqlKeywordRegexes = make(map[string]*regexp.Regexp)
)

func init() {
	for _, kw := range sqlKeywords {
		sqlKeywordRegexes[kw] = regexp.MustCompile(`(?i)\b` + kw + `\b`)
	}
}

type DDoSProtectionWAF struct {
	Stats         *WAFStats
	RateLimiter   *IPRateLimiter
	BanManager    *BanManager
	Listener      net.Listener
	ListenerMu    sync.Mutex
	Ctx           context.Context
	Cancel        context.CancelFunc
	MetricsServer *http.Server
	ActiveConns   sync.Map
	ConnLimiter   *IPConnLimiter
	SubnetBlocker *SubnetBlocker
}

func extractRealIP(conn net.Conn) string {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip == "127.0.0.1" || ip == "::1" || ip == "" { return "127.0.0.1" }
	return ip
}

func NewWAF() (*DDoSProtectionWAF, error) {
	stats := &WAFStats{}
	ctx, cancel := context.WithCancel(context.Background())
	sb := NewSubnetBlocker()
	sb.LoadFromDB()
	bm := NewBanManager(stats)
	bm.LoadBansFromDB()
	return &DDoSProtectionWAF{
		Stats:         stats,
		RateLimiter:   NewIPRateLimiter(),
		BanManager:    bm,
		Ctx:           ctx,
		Cancel:        cancel,
		ConnLimiter:   NewIPConnLimiter(),
		SubnetBlocker: sb,
	}, nil
}

func (waf *DDoSProtectionWAF) resetConnection(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// SetLinger(0) forces a TCP RST instead of a graceful FIN
		tcpConn.SetLinger(0)
	}
	conn.Close()
}

func (waf *DDoSProtectionWAF) handleConnection(clientConn net.Conn) {
	remoteIP := extractRealIP(clientConn)
	cfg := GetConfig()

	// Connection Limiting
	if waf.ConnLimiter.Add(remoteIP) > int32(cfg.MaxConnections) {
		waf.ConnLimiter.Done(remoteIP)
		waf.Stats.ConnectionLimitHits.Add(1)
		clientConn.Close()
		return
	}

	waf.Stats.ActiveConnections.Add(1)
	waf.ActiveConns.Store(clientConn, true)
	defer func() {
		waf.Stats.ActiveConnections.Add(-1)
		waf.ActiveConns.Delete(clientConn)
		waf.ConnLimiter.Done(remoteIP)
		clientConn.Close()
	}()

	bufReader := bufio.NewReader(clientConn)

	sendBlockPage := func(code int, title string, message string) {
		statusText := http.StatusText(code)
		if statusText == "" { statusText = "Forbidden" }
		body := fmt.Sprintf("%s | %s", message, title)
		resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Cache-Control: no-cache, no-store, must-revalidate\r\n"+
			"Pragma: no-cache\r\n"+
			"Expires: 0\r\n"+
			"Connection: close\r\n\r\n%s", code, statusText, len(body), body)
		clientConn.Write([]byte(resp))
		time.Sleep(50 * time.Millisecond)
	}

	isWhitelisted := waf.BanManager.IsWhitelisted(remoteIP)
	isBanned := false
	banReason := ""

	if !isWhitelisted {
		if waf.SubnetBlocker.IsBlocked(remoteIP) {
			isBanned = true
			banReason = "IP Blocked by Network Policy (CIDR)"
		} else if banned, reason := waf.BanManager.IsBlacklisted(remoteIP); banned {
			isBanned = true
			banReason = "IP Banned: " + reason
		}
	}

	if isBanned {
		waf.Stats.TotalRequests.Add(1)
		waf.Stats.BlockedRequests.Add(1)

		if _, warned := waf.BanManager.StealthWarned.Load(remoteIP); warned {
			waf.resetConnection(clientConn)
			return
		}

		// First attempt: Show message and mark as warned
		waf.BanManager.StealthWarned.Store(remoteIP, true)
		sendBlockPage(403, "NeoWAF", banReason)
		return
	}

	for {
		clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		req, err := http.ReadRequest(bufReader)
		if err != nil { return }
		waf.Stats.TotalRequests.Add(1)

		// Maintenance Mode Check (at Request Level)
		cfg = GetConfig() // Get fresh config state
		if cfg.MaintenanceMode && !isWhitelisted {
			if !cfg.MaintenanceExpires.IsZero() && time.Now().After(cfg.MaintenanceExpires) {
				cfg.MaintenanceMode = false
				cfg.MaintenanceExpires = time.Time{}
				SetConfig(cfg, "system")
			} else {
				waf.Stats.BlockedRequests.Add(1)
				// Log everything EXCEPT favicon to keep the console clean
				if req.URL.Path != "/favicon.ico" {
					log.Printf("[WAF] Blocked %s from %s (Maintenance Mode)", req.URL.Path, remoteIP)
				}
				sendBlockPage(503, "NeoWAF", cfg.BlockMessage)
				return
			}
		}
		
		
		if req.ContentLength > 10*1024*1024 {
			waf.Stats.BlockedRequests.Add(1)
			sendBlockPage(413, "NeoWAF", "Request Entity Too Large (Limit: 10MB)")
			return
		}

		var bodyBytes []byte
		if req.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		if WafEnabled.Load() && !isWhitelisted {
			if malicious, reason, score := isMaliciousRequest(req, bodyBytes); malicious {
				waf.Stats.BlockedRequests.Add(1)
				waf.incrementThreatStats(reason)
				waf.BanManager.RecordViolation(remoteIP, reason, score)
				log.Printf("[NUCLEAR-BLOCK] %s | Risk: %d | Path: %s", reason, score, req.URL.Path)
				LogSecurityAction(remoteIP, "Blocked: "+reason+" (Score: "+strconv.Itoa(score)+")")
				
				if _, warned := waf.BanManager.StealthWarned.Load(remoteIP); warned {
					// 2nd strike: Force a full ban so it appears in Active Restrictions
					cfg := GetConfig()
					waf.BanManager.BanWithReason(remoteIP, cfg.BanDuration, "Zero-Tolerance Security Policy: Critical Attack Sequence Detected")
					waf.resetConnection(clientConn)
					return
				}

				waf.BanManager.StealthWarned.Store(remoteIP, true)
				sendBlockPage(403, "NeoWAF", "Security Policy Violation: "+reason)
				return
			}
			if !waf.RateLimiter.Allow(remoteIP) {
				waf.Stats.BlockedRequests.Add(1)
				waf.incrementThreatStats("rate limit")
				sendBlockPage(429, "NeoWAF", "Rate Limit")
				return
			}
		}

		backendConn, err := net.DialTimeout("tcp", cfg.RealServer, 5*time.Second)
		if err != nil {
			waf.Stats.BlockedRequests.Add(1)
			sendBlockPage(502, "NeoWAF", "Backend Connection Failed")
			return
		}

		req.Write(backendConn)
		io.Copy(clientConn, backendConn)
		backendConn.Close()
		return 
	}
}

func (waf *DDoSProtectionWAF) Start() error {
	for {
		cfg := GetConfig()
		waf.ListenerMu.Lock()
		listener, err := net.Listen("tcp", cfg.WAFPort)
		if err != nil {
			waf.ListenerMu.Unlock()
			time.Sleep(5 * time.Second)
			continue
		}
		waf.Listener = listener
		waf.ListenerMu.Unlock()
		log.Printf("[SYSTEM] NeoWAF ABSOLUTE-ZERO Online on %s", cfg.WAFPort)
		for {
			conn, err := waf.Listener.Accept()
			if err != nil { break }
			go waf.handleConnection(conn)
		}
	}
}

func (waf *DDoSProtectionWAF) FlushConnections() {
	waf.ActiveConns.Range(func(key, value interface{}) bool {
		if conn, ok := key.(net.Conn); ok { conn.Close() }
		return true
	})
}

func (waf *DDoSProtectionWAF) Restart() {
	waf.ListenerMu.Lock()
	defer waf.ListenerMu.Unlock()
	if waf.Listener != nil { waf.Listener.Close() }
}

func (bm *BanManager) IsWhitelisted(ip string) bool {
	_, ok := whitelistCache.Load(ip)
	return ok
}

func (bm *BanManager) IsBlacklisted(ip string) (bool, string) {
	if v, ok := bm.bans.Load(ip); ok {
		b := v.(*BanInfo)
		if time.Now().Before(b.Until) { return true, b.Reason }
		bm.bans.Delete(ip)
	}
	var reason string
	err := db.QueryRow("SELECT reason FROM manual_blacklist WHERE ip = ?", ip).Scan(&reason)
	if err == nil { return true, reason }
	return false, ""
}

func (bm *BanManager) BanWithReason(ip string, duration time.Duration, reason string) {
	until := time.Now().Add(duration)
	bm.bans.Store(ip, &BanInfo{Until: until, Reason: reason})
	bm.Stats.TotalBans.Add(1)
	_, _ = db.Exec("INSERT OR REPLACE INTO active_bans (ip, reason, until, type) VALUES (?, ?, ?, ?)", ip, reason, until, "Auto")
}

func (bm *BanManager) RecordViolation(ip string, reason string, score int) {
	cfg := GetConfig()
	val, _ := bm.violations.LoadOrStore(ip, &atomic.Int32{})
	count := val.(*atomic.Int32)
	
	weight := 1
	// Detect critical security violations for immediate 2-strike banning
	criticalPatterns := []string{"SQLi", "XSS", "SSRF", "Traversal", "Zip Slip", "Bypass", "Injection", "Clobbering"}
	isCritical := false
	for _, p := range criticalPatterns {
		if strings.Contains(reason, p) {
			isCritical = true
			break
		}
	}

	if isCritical || score >= 100 {
		// Calculate weight based on dynamic security_strikes
		// weight * strikes = threshold => weight = threshold / strikes
		strikes := cfg.SecurityStrikes
		if strikes <= 0 { strikes = 2 }
		weight = int(cfg.BanThreshold) / strikes
		if weight < 1 { weight = 1 }
	}

	newCount := count.Add(int32(weight))
	if newCount >= int32(cfg.BanThreshold) {
		bm.BanWithReason(ip, cfg.BanDuration, "Zero-Tolerance Security Policy: Critical Attack Sequence Detected")
		bm.violations.Delete(ip)
		log.Printf("[SYSTEM-BAN] IP %s banned for %v | Reason: %s", ip, cfg.BanDuration, reason)
	} else if isCritical {
		strikesHit := int(newCount) / weight
		log.Printf("[STRIKE] IP %s | Strike %d/%d | Reason: %s", ip, strikesHit, cfg.SecurityStrikes, reason)
	}
}

func (bm *BanManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		bm.bans.Range(func(k, v interface{}) bool {
			if now.After(v.(*BanInfo).Until) { 
				bm.bans.Delete(k)
				bm.StealthWarned.Delete(k) // Clear warning when ban expires
				_, _ = db.Exec("DELETE FROM active_bans WHERE ip = ?", k)
			}
			return true
		})
	}
}

func isMaliciousRequest(req *http.Request, body []byte) (bool, string, int) {
	totalScore := 0
	reasons := []string{}
	var culpritSource, culpritData string

	// 1. PRE-NORMALIZATION
	originalPath := req.URL.Path
	originalQuery := req.URL.RawQuery
	req.URL.Path = pathNormalizer.ReplaceAllString(req.URL.Path, "/")
	
	if strings.Contains(originalQuery, "%2e%2e%2f") || strings.Contains(originalQuery, "%2e%2e%5c") || strings.Contains(originalPath, "%2e%2e%2f") {
		totalScore += 100
		reasons = append(reasons, "URL-Encoded Traversal")
	}

	deepDecode := func(input string) string {
		result := input
		for i := 0; i < MAX_DECODE_DEPTH; i++ {
			decoded, err := url.QueryUnescape(result)
			if err != nil || decoded == result { break }
			result = decoded
		}
		result = unicodeDecoder.ReplaceAllString(result, "..")
		return result
	}

	decodedPath := deepDecode(req.URL.Path)
	decodedQuery := deepDecode(req.URL.RawQuery)
	decodedBody := deepDecode(string(body))

	// 1.1 MULTIPART SQLi SCAN
	if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data") {
		// We use a copy of the body for parsing to avoid draining the original req.Body
		if err := req.ParseMultipartForm(10 * 1024 * 1024); err == nil {
			for _, values := range req.MultipartForm.Value {
				for _, v := range values {
					if malicious, r, s := checkMaliciousString(v, "Multipart-Value"); malicious {
						totalScore += s
						reasons = append(reasons, "Multipart SQLi: "+r)
					}
				}
			}
			for _, files := range req.MultipartForm.File {
				for _, f := range files {
					if malicious, r, s := checkMaliciousString(f.Filename, "Multipart-Filename"); malicious {
						totalScore += s
						reasons = append(reasons, "Multipart Filename Attack: "+r)
					}
				}
			}
			// Important: Reset body reader so backend can read it too
			if len(body) > 0 {
				req.Body = io.NopCloser(bytes.NewBuffer(body))
			}
		}
	}

	// 2. PATH & SENSITIVE CHECKS
	normPath := pathNormalizer.ReplaceAllString(decodedPath, "/")
	for _, s := range sensitiveFiles {
		if strings.Contains(normPath, s) || strings.Contains(decodedQuery, s) {
			totalScore += 100
			reasons = append(reasons, "Sensitive File Access")
		}
	}

	// 3. UNICODE & NESTED TRAVERSAL
	for _, p := range unicodeTraversalPatterns {
		if p.MatchString(originalPath) || p.MatchString(originalQuery) {
			totalScore += 90
			reasons = append(reasons, "Unicode Traversal Bypass")
		}
	}
	if nestedTraversalPattern.MatchString(decodedPath) || nestedTraversalPattern.MatchString(decodedQuery) {
		totalScore += 95
		reasons = append(reasons, "Nested Traversal Attack")
	}
	if zipSlipEnhanced.MatchString(decodedPath) || zipSlipEnhanced.MatchString(decodedQuery) {
		totalScore += 80
		reasons = append(reasons, "Zip Slip Escape")
	}

	// 4. SSRF & METHOD OVERRIDE
	for _, p := range ssrfPatterns {
		if p.MatchString(decodedPath) || p.MatchString(decodedQuery) {
			totalScore += 90
			reasons = append(reasons, "SSRF Attack")
		}
	}
	
	// DECIMAL IP BYPASS
	for _, source := range []string{decodedPath, decodedQuery, decodedBody} {
		if matches := decimalIPRegex.FindAllString(source, -1); len(matches) > 0 {
			for _, m := range matches {
				dotted := decimalToIP(m)
				if dotted != "" {
					for _, p := range ssrfPatterns {
						if p.MatchString(dotted) {
							totalScore += 95
							reasons = append(reasons, "Decimal IP SSRF Bypass: "+dotted)
						}
					}
				}
			}
		}
	}

	for _, h := range methodOverrideHeaders {
		if req.Header.Get(h) != "" {
			totalScore += 100
			reasons = append(reasons, "Method Override Bypass")
		}
	}

	// 5. CASE VARIATION & DOM CLOBBERING
	for _, kw := range sqlKeywords {
		p := sqlKeywordRegexes[kw]
		if p.MatchString(decodedQuery) {
			matches := p.FindAllString(decodedQuery, -1)
			for _, m := range matches {
				if m != strings.ToLower(m) && m != strings.ToUpper(m) {
					totalScore += 65
					reasons = append(reasons, "Mixed-Case SQL Bypass")
					break
				}
			}
		}
	}

	lowerBody := strings.ToLower(decodedBody)
	lowerQuery := strings.ToLower(decodedQuery)
	for _, p := range domPatterns {
		if strings.Contains(lowerBody, p) || strings.Contains(lowerQuery, p) {
			if strings.Contains(lowerBody, "<script") || strings.Contains(lowerBody, "alert(") || 
			   strings.Contains(lowerBody, "__proto__") || strings.Contains(lowerBody, "constructor") ||
			   strings.Contains(lowerBody, "document.cookie") {
				totalScore += 85
				reasons = append(reasons, "DOM Clobbering / Prototype Pollution")
				break
			}
		}
	}

	// 6. GENERAL HEURISTICS
	var inspect func(string, string)
	inspect = func(data string, source string) {
		if data == "" { return }
		if strings.Contains(data, "\x00") {
			totalScore += 90
			reasons = append(reasons, "Null Byte Injection")
		}

		// Base64 recursive scan
		if len(data) > 32 && !strings.Contains(data, " ") && !strings.HasPrefix(data, "http") {
			dec, err := base64.StdEncoding.DecodeString(data)
			if err == nil && len(dec) > 16 { inspect(string(dec), source+"(base64)") }
		}
		
		clean := data
		for i := 0; i < 3; i++ {
			decoded, _ := url.QueryUnescape(clean)
			if decoded == clean { break }
			clean = decoded
		}
		clean = strings.ReplaceAll(clean, "\x00", "")
		clean = strings.ReplaceAll(clean, "`", "'")
		clean = strings.ToLower(clean)
		clean = strings.Join(strings.Fields(clean), " ")

		if sqliHeuristic.MatchString(clean) {
			totalScore += 80
			reasons = append(reasons, "SQLi Pattern")
			culpritSource, culpritData = source, clean
		}
		if xssHeuristic.MatchString(clean) {
			if !strings.Contains(clean, " ") || bypassHeuristic.MatchString(clean) {
				totalScore += 80
				reasons = append(reasons, "XSS/SSTI Pattern")
				culpritSource, culpritData = source, clean
			}
		}
	}

	inspect(decodedPath, "Path")
	inspect(decodedQuery, "Query")
	for k, v := range req.Header {
		kL := strings.ToLower(k)
		if strings.HasPrefix(kL, "sec-") || kL == "user-agent" || kL == "accept" || kL == "cache-control" || kL == "connection" || kL == "pragma" || kL == "if-none-match" {
			continue 
		}
		inspect(strings.Join(v, " "), "Header:"+k)
	}
	if len(body) > 0 { inspect(decodedBody, "Body") }

	if totalScore >= 50 {
		if culpritSource != "" {
			log.Printf("[DEBUG] Blocked Source: %s | Data: %s", culpritSource, culpritData)
		}
		return true, strings.Join(uniqueStrings(reasons), " | "), totalScore
	}
	return false, "", 0
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func checkMaliciousString(data string, source string) (bool, string, int) {
	clean := strings.ToLower(data)
	
	// SQLi Check
	if sqliHeuristic.MatchString(clean) {
		return true, "SQLi Pattern in " + source, 80
	}
	
	// Zip Slip / Traversal Check
	if zipSlipEnhanced.MatchString(data) {
		return true, "Zip Slip / Traversal in " + source, 90
	}

	return false, "", 0
}

func decimalToIP(decimalStr string) string {
	dec, err := strconv.ParseUint(decimalStr, 10, 32)
	if err != nil {
		return ""
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(dec))
	return ip.String()
}
func (waf *DDoSProtectionWAF) incrementThreatStats(reason string) {
	parts := strings.Split(reason, " | ")
	for _, r := range parts {
		lr := strings.ToLower(r)
		if strings.Contains(lr, "sqli") || strings.Contains(lr, "sql") {
			waf.Stats.SQLiHits.Add(1)
		} else if strings.Contains(lr, "xss") || strings.Contains(lr, "dom") || strings.Contains(lr, "prototype") || strings.Contains(lr, "ssti") {
			waf.Stats.XSSHits.Add(1)
		} else if strings.Contains(lr, "traversal") || strings.Contains(lr, "zip slip") || strings.Contains(lr, "sensitive") {
			waf.Stats.TraversalHits.Add(1)
		} else if strings.Contains(lr, "ssrf") || strings.Contains(lr, "decimal ip") {
			waf.Stats.SSRFHits.Add(1)
		} else if strings.Contains(lr, "protocol") || strings.Contains(lr, "method override") || strings.Contains(lr, "null byte") {
			waf.Stats.ProtocolHits.Add(1)
		} else if strings.Contains(lr, "brute") || strings.Contains(lr, "credential") {
			waf.Stats.BruteforceHits.Add(1)
		} else if strings.Contains(lr, "rate limit") {
			waf.Stats.RateLimitHits.Add(1)
		}
	}
}
