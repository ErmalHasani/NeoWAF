package main

import (
	"io"
	"log"
	"os"
	"time"
	"NeoWAF/src"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetOutput(io.MultiWriter(os.Stdout, engine.SysLogs))
	engine.InitDB()
	engine.LoadConfig()

	waf, err := engine.NewWAF()
	if err != nil {
		log.Fatalf("[FATAL] WAF Init Error: %v", err)
	}

	engine.WafEnabled.Store(true)

	go engine.CollectMetricsLoop(waf)
	go waf.StartMetricsServer()
	go waf.Start()

	engine.RunPlatformSpecific(waf)

	// Graceful shutdown
	log.Println("[SYSTEM] Initiating graceful shutdown...")
	waf.Cancel()
	time.Sleep(2 * time.Second)
	if waf.MetricsServer != nil {
		waf.MetricsServer.Close()
	}
	log.Println("[SYSTEM] NeoWAF stopped.")
}
