package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	port := "8080"
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s from %s", time.Now().Format("15:04:05"), r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<!DOCTYPE html>
			<html>
			<head>
				<title>Test Backend - NeoWAF</title>
				<style>
					body { font-family: sans-serif; background: #121212; color: #eee; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
					.card { background: #1e1e1e; padding: 2rem; border-radius: 12px; border: 1px solid #333; text-align: center; }
					h1 { color: #3b82f6; }
					.status { color: #10b981; font-weight: bold; }
				</style>
			</head>
			<body>
				<div class="card">
					<h1>NeoWAF Test Backend</h1>
					<p>Status: <span class="status">Online & Protected</span></p>
					<p>Time: %s</p>
					<hr style="border: 0; border-top: 1px solid #333; margin: 1.5rem 0;">
					<p style="font-size: 0.8rem; color: #888;">This is a dummy backend for testing WAF connectivity.</p>
				</div>
			</body>
			</html>
		`, time.Now().Format(time.RFC1123))
	})

	fmt.Printf("🚀 Test Backend nisur në http://localhost:%s\n", port)
	fmt.Printf("Mund ta testosh përmes WAF në http://localhost:8888\n")
	
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
