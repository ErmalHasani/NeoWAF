//go:build !windows
package engine

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func RunPlatformSpecific(waf *DDoSProtectionWAF) {
	log.Println("[SYSTEM] Running in Headless Mode (Linux/Unix)")
	log.Println("[SYSTEM] Press Ctrl+C to shutdown.")

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	<-sigChan
	log.Println("[SYSTEM] NeoWAF shutting down...")
}

func HideFile(path string) {
	// On Linux, the dot prefix is enough. This is a no-op.
}
