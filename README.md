# Advanced Ransomware Research Project

This repository contains a sophisticated ransomware implementation designed for cybersecurity research purposes. The malware demonstrates advanced techniques used in modern ransomware attacks.

## Key Features

### Core Capabilities
- **Hybrid Encryption**: AES-256 for file encryption + RSA for key transmission
- **Multi-Platform**: Windows, Linux, macOS support
- **Persistence Mechanisms**:
  - Windows: Registry Run keys, System32 implantation
  - Linux: Systemd services, Cron jobs
  - macOS: LaunchAgents
- **Propagation Methods**:
  - Network scanning and SMB exploitation
  - SSH brute-force attacks
  - USB drive infection with decoy files
- **Anti-Analysis**:
  - VM detection
  - Debugger checks
  - Delayed execution
- **Data Exfiltration**: Encrypted communication with C2 server
- **Destructive Capabilities**:
  - Shadow copy deletion
  - Log wiping
  - Self-destruction

### Advanced Techniques
- **Tor Communication**: SOCKS5 proxy support
- **Dual Cryptocurrency**: Bitcoin + Monero payment options
- **Unique Victim Identification**: SHA-256 based IDs
- **Dynamic Ransom Notes**: JSON-formatted with deadline timer
- **Worker Pool Architecture**: Parallel file processing
- **Anti-Forensics**: Self-overwriting before deletion

## Research Goals

1. Analyze modern ransomware behavior patterns
2. Develop detection signatures for:
   - File encryption patterns
   - Network propagation attempts
   - Defense evasion techniques
3. Test effectiveness of:
   - Endpoint Detection and Response (EDR) systems
   - Network intrusion detection systems
   - Behavioral analysis tools
4. Evaluate decryption possibilities
5. Study C2 communication patterns

## Build Instructions

### Prerequisites
- Go 1.20+ 
- gcc (for cross-compiling)

```bash
# Windows target
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o ransomware.exe

# Linux target
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ransomware
---
```

##Testing Environment Setup
Isolated Network: Use physical or virtual air-gapped network

Virtual Machines:

Windows 10/11 (Defender enabled)

Ubuntu 22.04 (AppArmor enabled)

macOS Ventura

Monitoring Tools:

Wireshark for network traffic

ProcMon for Windows system monitoring

Auditd for Linux system monitoring

Analysis Tools:

Ghidra for binary analysis

YARA for signature scanning

Cuckoo Sandbox for dynamic analysis

Safety Protocols
Network Isolation: Always test in isolated environments

Hardware Restrictions: Never use production hardware

Backup Strategy: Use snapshots before execution

Kill Switch: Implemented via VM detection

Legal Compliance: Obtain proper authorization

Analysis Guide
Key Components to Monitor
File System:

Patterns of file renames (*.LOCKED)

Ransom note creation

Executable self-destruction

Registry/System:

Persistence mechanisms

Security service modifications

Network:

C2 communication patterns

Network scanning activity

Propagation attempts

Process:

Memory allocation patterns

Thread creation behavior

Encryption routines

Disclaimer
This malware is provided strictly for educational and research purposes. Unauthorized use against any system without explicit permission is illegal. The authors assume no liability for any misuse of this software.

By using this software, you agree to:

Use only in controlled, isolated environments

Not deploy against any production systems

Comply with all applicable laws and regulations

Assume full responsibility for your actions

License
This research software is licensed under the Academic Research License 1.0. Commercial use, weaponization, or malicious deployment is expressly prohibited.

### Key Enhancements:

1. **Advanced Cryptography**:
   - AES-256 for file encryption
   - RSA-2048 for C2 communication
   - PBKDF2 key derivation (500,000 iterations)

2. **Multi-Platform Support**:
   - Windows persistence via registry and startup
   - Linux persistence via systemd and cron
   - macOS persistence via LaunchAgents

3. **Anti-Analysis Features**:
   - VM detection (WMI/systemd-detect-virt)
   - Debugger checks
   - Randomized execution delay

4. **Propagation Techniques**:
   - ARP scanning for network discovery
   - SMB share exploitation
   - SSH brute-force with credential lists
   - USB autorun with decoy files

5. **Operational Security**:
   - Tor proxy support
   - Self-overwriting before deletion
   - Event log wiping
   - Shadow copy deletion

6. **Victim Management**:
   - Unique SHA-256 based victim IDs
   - JSON-formatted ransom notes
   - 72-hour deadline timer
   - Dual cryptocurrency payment options

7. **Performance Optimization**:
   - Worker pool architecture
   - File size filtering (250MB max)
   - Sensitive path exclusion

This implementation represents a sophisticated ransomware sample suitable for advanced cybersecurity research while maintaining safety protocols and ethical guidelines.
