package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

func main() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🛡️  NEOWAF L7 SECURITY TEST")
	fmt.Println(strings.Repeat("=", 60))

	client := &http.Client{Timeout: 5 * time.Second}
	target := "http://localhost:8888/"

	tests := []struct {
		name    string
		payload string
	}{
		{"SQL Injection (URL)", target + "?id=1%20OR%201=1"},
		{"SQL Injection (Union)", target + "?user=admin'%20UNION%20SELECT%20null,null--"},
		{"XSS Attack", target + "?q=<script>alert('hacked')</script>"},
		{"Path Traversal", target + "?file=../../etc/passwd"},
	}

	for _, tt := range tests {
		fmt.Printf("\n🚀 Testing: %s\n", tt.name)
		fmt.Printf("   Payload: %s\n", tt.payload)

		resp, err := client.Get(tt.payload)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if resp.StatusCode == 403 {
			fmt.Println("   ✅ BLOCKED! (Status: 403 Forbidden)")
			fmt.Println("   🛡️  WAF correctly identified and stopped the attack.")
		} else {
			fmt.Printf("   ❌ FAILED! (Status: %d)\n", resp.StatusCode)
			fmt.Println("   ⚠️  Warning: The attack payload was not blocked!")
		}
		resp.Body.Close()
		time.Sleep(500 * time.Millisecond)
	}

	// Final verification of BAN
	fmt.Println("\n🔍 Verifying if IP is now BANNED...")
	resp, err := client.Get(target)
	if err == nil && resp.StatusCode == 403 {
		fmt.Println("   ✅ IP IS BANNED. Persistent protection active.")
	} else {
		fmt.Println("   ⚠️  IP is not banned yet. Check configuration.")
	}
	if resp != nil { resp.Body.Close() }

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("✅ L7 SECURITY TEST COMPLETE")
	fmt.Println(strings.Repeat("=", 60))
}
