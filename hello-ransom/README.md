# HELLO RANSOMWARE RESEARCH EDITION - README

## Overview

The **Hello Ransom Research Edition** is an advanced ransomware *simulator* designed for security research and defensive testing. It is intended to operate **without admin privileges** and includes safety features for VM testing environments.

> **Important:** This project is for research and education only. Do **not** deploy on production or unauthorized systems.

---

## Key Features

### Safe Operation Mode

* **VM Detection:** Automatically detects virtual machines and adjusts behavior.
* **Non-Destructive:** No MBR overwrite or system file corruption.
* **Research Focus:** Clearly labeled as a research tool in all outputs and artefacts.
* **Safe File Sizes:** Limits encryption to files ≤ **50 MB**.

### Advanced Encryption

**Hybrid Cryptosystem:**

* **AES-256-GCM** for symmetric file encryption.
* **RSA-4096** for encrypting symmetric keys.
* **PBKDF2** for key derivation (300,000 iterations).
* **File Selection:** Targets user documents only (document formats and user profile dirs).
* **Parallel Processing:** 32-thread encryption engine for simulation speed.

### Persistence Mechanisms (Non-Admin)

* **Registry (HKCU):** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* **Startup Folder:** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
* **AppData Copy:** Executable copied to `%APPDATA%\Microsoft\Windows\helloransom.exe`

### Evasion Techniques (Simulated)

* Anti-debugging checks (non-destructive)
* Randomized filenames for simulated operations
* Memory-only operations where possible
* **No network callbacks** by default (configurable)
* VM-aware operational adjustments

### User Interaction

* Desktop wallpaper modification (configurable / non-destructive)
* Multiple ransom notes dropped in user directories
* Interactive popup notifications with research labeling

---

## Safety Features

```go
const SAFE_MODE = true // Enable all safety features

// Safety implementations:
// 1. No system modification
// 2. VM detection skips destructive operations
// 3. Limited file size encryption
// 4. Research warnings in all messages
// 5. No privilege escalation attempts
```

---

## Testing Protocol

### Recommended Environment

* **Virtualization:** VMware Workstation 17+ or VirtualBox 7.0+
* **OS:** Windows 10 / 11 (64-bit)
* **Tools:**

  * Wireshark (network analysis)
  * Process Monitor (behavior analysis)
  * REMnux (malware analysis toolkit)

### Test Procedure

1. **Build executable:**

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o hello_research.exe
```

2. **Execute in VM:**

```powershell
Start-Process .\hello_research.exe
```

3. **Monitor effects:**

* Check user document encryption
* Verify persistence entries
* Note visual effects and popups
* Revert VM snapshot for repeated testing

---

## Expected Behavior

* Copies itself to `%APPDATA%\Microsoft\Windows\`
* Creates persistence entries (HKCU Run, Startup LNK)
* Encrypts user documents with `.HELLORANSOM` extension
* Displays ransom notes on Desktop and Documents folders
* Shows **3 popup notifications** during run
* Changes desktop wallpaper (disabled in SAFE\_MODE on non-VMs)

---

## Recovery Procedure

1. **Remove persistence:**

```reg
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v HelloRansomResearch /f
```

2. **Delete files:**

```powershell
Remove-Item "$env:APPDATA\Microsoft\Windows\helloransom.exe"
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\HelloRansom.lnk"
```

3. Restore files using the included decryption tool (follow the decryption tool instructions).

---

## Ethical Guidelines

* **Legal Compliance:** Use only in controlled, authorized environments.
* **Authorization:** Never deploy without explicit written permission.
* **Disclosure:** Clearly label all outputs as a research tool.
* **Containment:** Isolate test environments from production networks.
* **Responsibility:** Researchers accept full responsibility for usage.

---

## Research Applications

* Defense strategy development
* Detection engineering
* Incident response training
* Behavioral analysis
* Honeypot enhancement

---

## Q\&A

**Q: How does it avoid VM detection?**
A: When `SAFE_MODE=true`, destructive operations are skipped but core simulation functionality still runs.

**Q: Can this infect real systems?**
A: It is designed for research and can modify user files; **always** use within VM snapshots.

**Q: How to get decryption tool?**
A: Contact `nskj546@gmail.com` with a research proposal.

**Q: What if it escapes the VM?**
A: The tool includes network isolation checks and will refuse to execute destructive flows when SAFE\_MODE is enabled.

---

## Disclaimer

```
This is a research tool provided for educational purposes only. The authors
disclaim all responsibility for unauthorized use or damages caused by misuse.
Always obtain proper authorization before use and follow ethical guidelines
for malware research.
```

---

## Contact

* **Research collaboration:** [nskj546@gmail.com](mailto:nskj546@gmail.com)
* **PGP Key:** Available upon request
*
---

*This version maintains advanced ransomware capabilities while prioritizing safety and research ethics. It includes explicit warnings and safety mechanisms to prevent accidental damage while still providing realistic behavioral patterns for defensive research.*
