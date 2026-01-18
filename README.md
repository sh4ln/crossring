# CROSSRING

**Universal Zero-Trust Offline Endpoint Security System**

A comprehensive, owner-controlled security platform that protects Windows and Linux systems using a "Never Trust, Always Verify" approach. Designed for users on both modern and legacy (EOL) operating systems.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)](#platform-support)
[![Version](https://img.shields.io/badge/Version-1.0.23-orange.svg)](#)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Platform Support](#platform-support)
- [Installation](#installation)
- [Building from Source](#building-from-source)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Protection

| Feature | Description |
|---------|-------------|
| Zero Trust Engine | Risk-based scoring (0-100) for every process |
| Process Monitoring | Real-time execution tracking via ETW/eBPF |
| Script Scanning | AMSI integration (Win10+) or pattern matching |
| Memory Scanning | Detect fileless malware via unbacked pages |
| Persistence Monitoring | Registry, startup, cron, systemd watching |
| Network Monitoring | TCP/UDP tracking with phantom detection |
| USB Blocking | Prevent execution from removable drives |

### Advanced Security (Universal Zero Trust)

| Feature | Description |
|---------|-------------|
| Self-Immunity | Symlink-resistant protection with SHA256 verification |
| Safe Mode Challenge | Visual CAPTCHA (image-based) killswitch |
| Event-Driven Cache | Race-condition safe system updates |
| Atomic Cert Trust | TOCTOU-resistant certificate whitelisting |
| Smart Kill Loop | 4-step: Graceful to Forced to Kernel termination |
| HMAC-Signed Config | Tamper-resistant configuration with time locks |
| OS Integrity Checks | SecureBoot, HVCI, SELinux, AppArmor detection |

### Passive Monitoring (Non-Blocking)

| Feature | Description |
|---------|-------------|
| Kernel Integrity | Driver signing, syscall hook, hidden process detection |
| Injection Detection | Monitor WriteProcessMemory, with debugger whitelist |
| Update Protection | Never block Windows Update, apt, yum, pacman |
| Backup and Recovery | Quarantine with restore, config rollback |
| Resource Limits | 5% CPU cap, 150MB RAM, low I/O priority |
| Zero Telemetry | No network connections, local logs only |

### User Experience

- Modern WPF/GTK4 dashboard
- Real-time toast notifications
- Per-user configuration
- Event logging and export
- First-run wizard with protection modes

---

## Architecture

```
CROSSRING/
├── CrossringService/          # Windows C++ Service (16 source files)
│   ├── include/               # Headers
│   │   ├── SecurityCore.h     # Universal Zero Trust API
│   │   ├── EtwMonitor.h       # ETW process tracing
│   │   ├── AmsiScanner.h      # Script scanning
│   │   ├── ZeroTrust.h        # Risk scoring engine
│   │   └── ...
│   └── src/                   # Implementation
│       ├── SecurityCore.cpp   # Self-immunity, Safe mode, Kill loop
│       ├── SecurityCore2.cpp  # Cache, Cert trust, Config, OS checks
│       ├── EtwMonitor.cpp     # ETW consumer
│       ├── LegacySupport.cpp  # Windows 7/8 fallbacks
│       └── ...
│
├── CrossringUI/               # Windows WPF GUI
│   ├── Views/
│   │   ├── MainWindow.xaml    # Dashboard
│   │   ├── AuthPromptWindow.xaml
│   │   ├── FirstRunDialog.xaml
│   │   ├── LimitedModeDialog.xaml
│   │   └── SettingsWindow.xaml
│   └── Services/
│       ├── PipeClient.cs      # IPC
│       └── NotificationService.cs
│
├── linux/                     # Linux Daemon + GTK4 GUI
│   ├── src/
│   │   ├── main.cpp           # Daemon entry
│   │   ├── process_monitor.cpp # eBPF/procfs
│   │   ├── apparmor_policy.cpp
│   │   └── security_core.cpp  # Zero Trust for Linux
│   └── gui/
│       └── main.c             # GTK4 interface
│
├── vendor/                    # Dependencies
│   ├── sqlite/                # SQLite amalgamation
│   └── json/                  # nlohmann/json
│
└── Installer/                 # Inno Setup scripts
```

---

## Platform Support

| Platform | Process Monitor | App Control | Script Scan | Status |
|----------|-----------------|-------------|-------------|--------|
| Windows 11 | ETW | AppLocker/WDAC | AMSI | Full Support |
| Windows 10 | ETW | AppLocker/WDAC | AMSI | Full Support |
| Windows 8.1 | WMI | Group Policy | Patterns | Legacy Mode |
| Windows 7 | WMI | Group Policy | Patterns | EOL Support |
| Ubuntu/Debian | eBPF/procfs | AppArmor | Patterns | Full Support |
| Fedora/RHEL | eBPF/procfs | SELinux | Patterns | Full Support |

> **Note**: Windows 7 Support - While CROSSRING works on Windows 7, Microsoft no longer provides security updates. We recommend upgrading for best protection.

---

## Installation

### Windows

**Option 1: Installer**
```powershell
# Download and run
CrossringSetup.exe
```

**Option 2: Manual**
```powershell
# Install service (requires Admin)
.\CrossringService.exe /install

# Start service
net start CrossringService

# Launch GUI
.\CrossringUI.exe
```

### Linux

**Ubuntu/Debian**
```bash
sudo dpkg -i crossring_1.0.23_amd64.deb
sudo systemctl enable --now crossring
crossring-gui
```

**Fedora/RHEL**
```bash
sudo rpm -i crossring-1.0.23.x86_64.rpm
sudo systemctl enable --now crossring
crossring-gui
```

**AppImage (Universal)**
```bash
chmod +x crossring-1.0.23.AppImage
./crossring-1.0.23.AppImage
```

---

## Building from Source

### Windows Requirements

- Visual Studio 2022
- Windows SDK 10.0.22000+
- .NET 8 SDK

### Linux Requirements

- CMake 3.16+
- GCC 10+ or Clang 12+
- libsqlite3-dev
- libgtk-4-dev (for GUI)
- libbpf-dev (optional, for eBPF)
- libcap-dev

### Build Commands

**Windows**
```powershell
git clone https://github.com/sh4ln/crossring.git
cd crossring
# Open CROSSRING.sln in Visual Studio
# Build -> Build Solution (Release | x64)
```

**Linux**
```bash
git clone https://github.com/sh4ln/crossring.git
cd crossring/linux
./build.sh all
```

---

## Configuration

### Protection Modes

| Mode | Behavior | Recommended For |
|------|----------|-----------------|
| Monitoring | Logs only, allows everything | First 7 days (testing) |
| Balanced | Blocks threats, prompts for unknown | Most users (default) |
| Zero Trust | Blocks ALL unsigned/unknown | Security professionals |

### Configuration Files

**Windows**
- Service config: `C:\ProgramData\CROSSRING\config.xml`
- User whitelist: `C:\ProgramData\CROSSRING\safe_paths.txt`
- Database: `C:\ProgramData\CROSSRING\database.db`

**Linux**
- Daemon config: `/etc/crossring/config.xml`
- User whitelist: `/etc/crossring/safe_paths.conf`
- Database: `/var/lib/crossring/database.db`

### Whitelist Format

```
# One path per line, wildcards supported
C:\MyApps\*
/opt/custom-tools/*
# Comments start with #
```

---

## Security Model

### Zero Trust Risk Scoring

Every process is evaluated against multiple factors:

| Risk Factor | Score | Description |
|-------------|-------|-------------|
| Unsigned executable | +20 | No digital signature |
| Temp/Downloads folder | +25 | Suspicious location |
| USB drive | +30 | Removable media |
| Obfuscated script | +35 | Base64/encoding detected |
| Known bad hash | +100 | Matches threat database |
| LOLBin with args | +40 | PowerShell -enc, etc. |

| Trust Factor | Score | Description |
|--------------|-------|-------------|
| Microsoft signed | -40 | Trusted publisher |
| Whitelisted | -100 | User approved |
| System path | -25 | C:\Windows\System32 |

**Decision Thresholds:**
- Score >= 50: Requires user authorization
- Score >= 80: Blocked by default

### Self-Protection Features

1. **Symlink Resistance**: Resolves canonical paths before protection checks
2. **Hash Verification**: SHA256 of protected binaries stored in memory
3. **TOCTOU Defense**: File hash checked immediately before execution
4. **Tamper-Proof Config**: HMAC-SHA256 signature, anti-rollback

### Smart Process Termination

```
Step 1: Graceful (SIGTERM / WM_CLOSE) - Wait 5 seconds
Step 2: Forced (SIGKILL / TerminateProcess)
Step 3: Kernel (ZwTerminateProcess / cgroup)
Step 4: Alert if still running (possible rootkit)
```

---

## API Reference

### Windows Service Control

```powershell
CrossringService.exe /install    # Install service
CrossringService.exe /uninstall  # Remove service
CrossringService.exe /console    # Run in console mode (debug)
```

### Named Pipe IPC

```
Pipe Name: \\.\pipe\CrossringPipe
Protocol: JSON over UTF-8

Request:
{ "type": "decision", "pid": 1234, "action": "allow" }

Events:
{ "type": "process", "pid": 1234, "path": "...", "risk": 45 }
{ "type": "memory_anomaly", "pid": 1234, "region": "0x..." }
```

### Linux D-Bus (planned)

```
Bus: system
Interface: com.crossring.daemon
Methods: Allow(pid), Deny(pid), GetStatus()
Signals: ProcessBlocked, ThreatDetected
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes with tests
4. Submit Pull Request

### Code Style

- C++: C++17, Microsoft guidelines, RAII
- C#: .NET conventions, MVVM pattern
- Linux: POSIX compliant, SELinux aware

---

## Project Statistics

| Component | Files | Lines | Size |
|-----------|-------|-------|------|
| Windows Service | 16 cpp | ~4,000 | 150 KB |
| Windows GUI | 20 xaml/cs | ~2,000 | 45 KB |
| Linux Daemon | 7 cpp | ~1,500 | 30 KB |
| Linux GUI | 2 c | ~400 | 10 KB |
| **Total** | **45+ files** | **~8,000** | **~235 KB** |

---

## License

MIT License - See [LICENSE.txt](LICENSE.txt)

---

## Acknowledgments

- [SQLite](https://sqlite.org/) - Public domain database
- [nlohmann/json](https://github.com/nlohmann/json) - JSON for Modern C++
- [Hardcodet.NotifyIcon](https://github.com/hardcodet/wpf-notifyicon) - WPF system tray

---

<p align="center">
  <b>CROSSRING</b> - Owner-Controlled Security for Everyone
  <br>
  <i>"Never Trust, Always Verify"</i>
  <br><br>
  Version 1.0.23
</p>
