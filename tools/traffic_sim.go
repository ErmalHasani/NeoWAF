package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

func main() {
	target := "http://localhost:8888"
	
	fmt.Printf("🚀 NeoWAF Dynamic Traffic Simulator\n")
	fmt.Printf("🎯 Target: %s\n", target)
	fmt.Printf("⚡ Pattern: Randomized (10-45 req/sec)\n")
	fmt.Println("------------------------------------------")

	ticker := time.NewTicker(200 * time.Millisecond) // 5 ticks per second
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	rand.Seed(time.Now().UnixNano())

	for range ticker.C {
		// Random requests for this 200ms slice (target 10-45 per sec)
		// 10/5 = 2 min, 45/5 = 9 max
		count := rand.Intn(8) + 2 
		
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(target)
				if err != nil { return }
				resp.Body.Close()
			}()
		}
		wg.Wait()
		fmt.Printf("[%s] 🌪️ Dynamic Burst: %d requests\n", time.Now().Format("15:04:05"), count)
	}
}
