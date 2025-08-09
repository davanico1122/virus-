# Advanced Ransomware Research Module (Windows Destruction)

**WARNING: This software is for research purposes only. Use only in controlled environments. Misuse is illegal.**

## Overview
This ransomware module is designed for advanced cybersecurity research focusing on Windows system vulnerabilities. It implements destructive techniques to completely disable a Windows system while encrypting user files. The module includes sophisticated anti-analysis techniques and persistence mechanisms.

## Key Features
- **AES-256 File Encryption**: Encrypts over 20 file types with military-grade encryption
- **MBR Overwrite**: Replaces Master Boot Record with destructive payload
- **Shadow Copy Elimination**: Permanently deletes system restore points
- **Registry Destruction**: Corrupts critical registry entries
- **USB Propagation**: Spreads via USB devices with autorun.inf
- **Anti-Analysis**: Anti-debugging and sandbox evasion techniques
- **Self-Destruction**: Clears evidence and forces immediate reboot

## Attack Sequence
1. **Initialization**: Anti-analysis checks and victim ID generation
2. **File Encryption**: Parallel encryption of user files across all directories
3. **System Destruction**:
   - MBR overwrite (boot loop)
   - Shadow copy deletion
   - Registry corruption
   - Recovery mechanism disablement
4. **Propagation**: USB device infection
5. **Finalization**: System reboot to activate MBR payload

## Technical Specifications
- **Encryption**: AES-256-GCM with PBKDF2 key derivation (100,000 iterations)
- **Persistence**: Registry modifications and startup entries
- **Evasion**: Time-delayed execution and anti-debugging
- **Propagation**: USB autorun.inf technique
- **Payload**: Custom MBR boot sector that causes immediate boot failure

## Research Value
- Study modern ransomware techniques in controlled environment
- Analyze Windows boot process vulnerabilities
- Develop defensive strategies against MBR attacks
- Test detection capabilities for fileless persistence

## Usage Instructions
1. Compile with: `go build -ldflags="-H=windowsgui" ransomware.go`
2. Execute on Windows test machine (VM recommended)
3. Observe system behavior during attack sequence
4. After reboot, system will be completely inoperable

## Safety Precautions
- Use only in isolated virtual machines with no network access
- Disable shared folders and clipboard in VM settings
- Take VM snapshots before execution
- Store encryption keys securely for potential recovery

## Ethical Considerations
- Never test on unauthorized systems
- Completely illegal to use outside research environments
- All researchers must follow institutional review processes
- Report vulnerabilities responsibly

## Recovery Process (For Research)
1. Restore from VM snapshot
2. For physical machines: Reinstall OS and restore files from backup
3. Without backup: Data recovery impossible due to strong encryption

## Disclaimer
This tool is provided solely for educational and research purposes. The author assumes no liability for any misuse or damage caused by this software.
