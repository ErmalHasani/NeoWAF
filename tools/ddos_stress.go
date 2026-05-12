package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	target := "http://localhost:8888" // WAF Endpoint
	concurrentRequests := 50         // Sa "sulmues" paralelë
	totalRequests := 500             // Totali i kërkesave

	fmt.Printf("🚀 Duke nisur Stress Test mbi %s...\n", target)
	fmt.Printf("📊 Konfigurimi: %d kërkesa paralele, %d totale.\n", concurrentRequests, totalRequests)

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrentRequests)
	
	start := time.Now()
	blockedCount := 0
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sem <- struct{}{}        // Merr slotin
			defer func() { <-sem }() // Liro slotin

			resp, err := http.Get(target)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			if resp.StatusCode == 429 || resp.StatusCode == 403 {
				blockedCount++
			} else if resp.StatusCode == 200 {
				successCount++
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	fmt.Println("\n--- REZULTATET E TESTIT ---")
	fmt.Printf("⏱️ Kohëzgjatja: %v\n", duration)
	fmt.Printf("✅ Kërkesa të kaluara (200 OK): %d\n", successCount)
	fmt.Printf("🚫 Kërkesa të bllokuara (429/403): %d\n", blockedCount)
	
	if blockedCount > 0 {
		fmt.Println("\n🛡️ NeoWAF REZULTOI I SUKSESSHËM! Mbrojtja u aktivizua.")
	} else {
		fmt.Println("\n⚠️ NeoWAF nuk bllokoi asnjë kërkesë. Kontrollo limitet në Dashboard → WAF Configuration.")
	}
}
