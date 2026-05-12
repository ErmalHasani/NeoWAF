# NeoWAF

A high-performance, self-hosted **Web Application Firewall (WAF)** and **DDoS protection proxy** written in Go. Inspect, filter, and monitor all HTTP traffic in real-time with a modern security dashboard.

---

## ✨ Features

| Category | Details |
|---|---|
| **L7 Inspection** | SQLi, XSS, Path Traversal, SSRF, Command Injection, Zip Slip, DOM Clobbering, Null Byte, Parameter Pollution, and more |
| **DDoS Mitigation** | Token bucket rate limiting per-IP, max connection tracking, automatic banning |
| **Zero-Tolerance Banning** | Strike-based system that auto-bans IPs exceeding configurable thresholds |
| **Real-Time Dashboard** | Live metrics, L7 traffic chart, threat intelligence, system health |
| **IP Management** | Manual whitelist/blacklist, CIDR/subnet blocking, auto-unban support |
| **Multi-User Access** | Role-based access control (RBAC), configurable permissions per user |
| **Maintenance Mode** | One-click traffic blocking with custom messages and optional auto-expiry |
| **System Tray** | Native Windows tray icon with dashboard and console controls |

---

## 🖥️ Compatibility

| OS | Status |
|---|:---:|
| Windows | ✅ Fully supported |
| Linux | ✅ Fully supported |
| macOS | ❓ Untested |

---

## 🚀 Quick Start

**Prerequisites:** Go 1.21+

```bash
# Clone
git clone https://github.com/ErmalHasani/NeoWAF.git
cd NeoWAF

# Install dependencies
go mod tidy

# Run
go run .
```

The WAF starts on two ports:
- **`:8888`** — WAF listener (proxies to your real backend)
- **`:9090`** — Security Dashboard (default login: `admin` / `admin`)

> ⚠️ **Change the admin password immediately** after the first login via the Account Management panel.

---

## ⚙️ Configuration

All configuration is managed through the **Web Dashboard**:

- 🔧 **Real-time settings** — Change WAF parameters instantly
- 💾 **Export/Import** — Backup and restore configurations
- 🔄 **Reset to defaults** — One-click factory reset
- 📜 **Audit history** — See who changed what and when (admin-only)

> ⚠️ **No configuration file is stored on disk** — all settings are persisted in the SQLite database.

---

## 🏗️ Build

**Windows:**
```bash
go build -ldflags="-H windowsgui" -o NeoWAF.exe ./src
```

**Linux:**
```bash
go build -o neowaf ./src
```

**Cross-compile from Windows to Linux:**
```bash
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o neowaf ./src
```
---

## 📄 License

[MIT License](LICENSE) — © 2026 NeoWAF Team
