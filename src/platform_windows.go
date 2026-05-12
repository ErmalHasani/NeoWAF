//go:build windows
package engine

import (
	"fmt"
	"log"
	"syscall"
	"time"
	_ "embed"
	"github.com/getlantern/systray"
	"github.com/pkg/browser"
)

//go:embed assets/icon.png
var iconData []byte

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	user32             = syscall.NewLazyDLL("user32.dll")
	getConsoleWindow   = kernel32.NewProc("GetConsoleWindow")
	showWindow         = user32.NewProc("ShowWindow")
)

const (
	SW_HIDE = 0
	SW_SHOW = 5
)

func setConsoleVisible(visible bool) {
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 { return }
	if visible {
		showWindow.Call(hwnd, SW_SHOW)
	} else {
		showWindow.Call(hwnd, SW_HIDE)
	}
}

func wrapPngAsIco(pngData []byte) []byte {
	header := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00}
	entry := make([]byte, 16)
	entry[0], entry[1], entry[6] = 0, 0, 32
	size := uint32(len(pngData))
	entry[8], entry[9], entry[10], entry[11] = byte(size), byte(size>>8), byte(size>>16), byte(size>>24)
	offset := uint32(22)
	entry[12], entry[13], entry[14], entry[15] = byte(offset), byte(offset>>8), byte(offset>>16), byte(offset>>24)
	res := append(header, entry...)
	return append(res, pngData...)
}

func RunPlatformSpecific(waf *DDoSProtectionWAF) {
	systray.Run(func() { onReady(waf) }, onExit)
}

func onReady(waf *DDoSProtectionWAF) {
	systray.SetIcon(wrapPngAsIco(iconData))
	systray.SetTitle("NeoWAF Firewall")
	systray.SetTooltip("NeoWAF - Active Protection")

	mOpen := systray.AddMenuItem("Open Dashboard", "Open the WAF Dashboard")
	mConsole := systray.AddMenuItem("Show Console", "Toggle terminal visibility")
	systray.AddSeparator()
	mEnable := systray.AddMenuItemCheckbox("WAF Enabled", "Enable/Disable protection", true)
	systray.AddSeparator()
	mRestart := systray.AddMenuItem("Restart WAF", "Restart the listener")
	mQuit := systray.AddMenuItem("Quit", "Shutdown NeoWAF")

	dashboardURL := fmt.Sprintf("http://localhost:%d", GetConfig().MetricsPort)

	go func() {
		log.Println("[SYSTEM] NeoWAF is initializing...")
		log.Println("[SYSTEM] Terminal will hide and browser will open in 3 seconds.")
		time.Sleep(3 * time.Second)
		log.Printf("[SYSTEM] Opening Dashboard: %s", dashboardURL)
		browser.OpenURL(dashboardURL)
		log.Println("[SYSTEM] Hiding terminal window. Access control via system tray.")
		time.Sleep(1 * time.Second)
		setConsoleVisible(false)
	}()

	consoleVisible := false
	for {
		select {
		case <-mOpen.ClickedCh:
			browser.OpenURL(dashboardURL)
		case <-mConsole.ClickedCh:
			consoleVisible = !consoleVisible
			setConsoleVisible(consoleVisible)
			if consoleVisible {
				mConsole.SetTitle("Hide Console")
			} else {
				mConsole.SetTitle("Show Console")
			}
		case <-mEnable.ClickedCh:
			if mEnable.Checked() {
				mEnable.Uncheck()
				WafEnabled.Store(false)
			} else {
				mEnable.Check()
				WafEnabled.Store(true)
			}
		case <-mRestart.ClickedCh:
			waf.Restart()
		case <-mQuit.ClickedCh:
			systray.Quit()
		}
	}
}

func onExit() {
	log.Println("[SYSTEM] NeoWAF shutting down...")
}

func HideFile(path string) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	// 0x02 is FILE_ATTRIBUTE_HIDDEN
	syscall.SetFileAttributes(ptr, 0x02)
}
