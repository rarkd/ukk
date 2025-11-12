import socket
import hashlib
import binascii
import subprocess
import re
import platform

class MikrotikAPI:
    def __init__(self, mac_address=None, host=None, port=8728):
        """
        Inisialisasi dengan MAC address atau IP host
        mac_address: MAC address Mikrotik (format: AA:BB:CC:DD:EE:FF atau AA-BB-CC-DD-EE-FF)
        host: IP address Mikrotik (jika tidak pakai MAC)
        """
        self.mac_address = mac_address
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False
    
    def find_ip_by_mac(self, mac_address):
        """Mencari IP berdasarkan MAC address di jaringan lokal"""
        try:
            # Normalisasi format MAC address
            mac_clean = mac_address.upper().replace('-', ':')
            
            print(f"Mencari IP untuk MAC: {mac_clean}")
            
            # Deteksi OS
            os_type = platform.system()
            
            if os_type == "Windows":
                # Windows: gunakan arp -a
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
                
                # Parse output arp
                for line in output.split('\n'):
                    if mac_clean.replace(':', '-') in line.upper():
                        # Extract IP address
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            print(f"IP ditemukan: {ip}")
                            return ip
            
            elif os_type == "Linux":
                # Linux: gunakan arp -n atau ip neigh
                try:
                    output = subprocess.check_output("ip neigh show", shell=True).decode('utf-8')
                except:
                    output = subprocess.check_output("arp -n", shell=True).decode('utf-8')
                
                for line in output.split('\n'):
                    if mac_clean in line.upper() or mac_clean.replace(':', '-') in line.upper():
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            print(f"IP ditemukan: {ip}")
                            return ip
            
            elif os_type == "Darwin":  # macOS
                output = subprocess.check_output("arp -a", shell=True).decode('utf-8')
                
                for line in output.split('\n'):
                    if mac_clean in line.upper() or mac_clean.replace(':', '-') in line.upper():
                        ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            print(f"IP ditemukan: {ip}")
                            return ip
            
            print(f"IP tidak ditemukan untuk MAC: {mac_clean}")
            print("Pastikan Mikrotik sudah terhubung ke jaringan dan sudah melakukan komunikasi")
            print("Coba ping IP Mikrotik terlebih dahulu, lalu jalankan lagi script ini")
            return None
            
        except Exception as e:
            print(f"Error saat mencari IP: {e}")
            return None
    
    def scan_network_for_mac(self, mac_address, subnet="192.168.80"):
        """Scan jaringan untuk menemukan IP dengan MAC tertentu"""
        try:
            mac_clean = mac_address.upper().replace('-', ':')
            print(f"Scanning network {subnet}.0/24 untuk MAC: {mac_clean}")
            
            # Ping semua IP di subnet untuk populate ARP table
            for i in range(1, 255):
                ip = f"{subnet}.{i}"
                if platform.system() == "Windows":
                    subprocess.Popen(f"ping -n 1 -w 100 {ip}", 
                                   shell=True, 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
                else:
                    subprocess.Popen(f"ping -c 1 -W 1 {ip}", 
                                   shell=True, 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
            
            # Tunggu sebentar untuk ARP table terisi
            import time
            time.sleep(3)
            
            # Cari di ARP table
            return self.find_ip_by_mac(mac_address)
            
        except Exception as e:
            print(f"Error saat scanning: {e}")
            return None
    
    def connect(self):
        """Membuat koneksi ke Mikrotik"""
        try:
            # Jika menggunakan MAC address, cari IP-nya dulu
            if self.mac_address and not self.host:
                self.host = self.find_ip_by_mac(self.mac_address)
                
                # Jika tidak ditemukan, coba scan network
                if not self.host:
                    print("\nMencoba scan network...")
                    self.host = self.scan_network_for_mac(self.mac_address)
                
                if not self.host:
                    print("Gagal menemukan IP dari MAC address")
                    return False
            
            # Buat koneksi socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)  # Timeout 5 detik
            self.sock.connect((self.host, self.port))
            self.connected = True
            print(f"Terhubung ke {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"Gagal terhubung: {e}")
            return False
    
    def send_length(self, data):
        """Mengirim panjang data sesuai protokol Mikrotik"""
        length = len(data)
        if length < 0x80:
            self.sock.send(bytes([length]))
        elif length < 0x4000:
            self.sock.send(bytes([length >> 8 | 0x80, length & 0xFF]))
        elif length < 0x200000:
            self.sock.send(bytes([length >> 16 | 0xC0, length >> 8 & 0xFF, length & 0xFF]))
        elif length < 0x10000000:
            self.sock.send(bytes([length >> 24 | 0xE0, length >> 16 & 0xFF, length >> 8 & 0xFF, length & 0xFF]))
        else:
            self.sock.send(bytes([0xF0, length >> 24 & 0xFF, length >> 16 & 0xFF, length >> 8 & 0xFF, length & 0xFF]))
    
    def send_word(self, word):
        """Mengirim kata (word) sesuai protokol Mikrotik"""
        self.send_length(word)
        self.sock.send(word.encode('utf-8'))
    
    def send_sentence(self, words):
        """Mengirim kalimat (sentence) yang terdiri dari beberapa kata"""
        for word in words:
            self.send_word(word)
        self.sock.send(b'\x00')
    
    def read_length(self):
        """Membaca panjang data dari socket"""
        c = self.sock.recv(1)[0]
        if c & 0x80 == 0x00:
            return c
        elif c & 0xC0 == 0x80:
            return ((c & ~0xC0) << 8) + self.sock.recv(1)[0]
        elif c & 0xE0 == 0xC0:
            return ((c & ~0xE0) << 16) + (self.sock.recv(1)[0] << 8) + self.sock.recv(1)[0]
        elif c & 0xF0 == 0xE0:
            return ((c & ~0xF0) << 24) + (self.sock.recv(1)[0] << 16) + (self.sock.recv(1)[0] << 8) + self.sock.recv(1)[0]
        elif c & 0xF8 == 0xF0:
            return (self.sock.recv(1)[0] << 24) + (self.sock.recv(1)[0] << 16) + (self.sock.recv(1)[0] << 8) + self.sock.recv(1)[0]
    
    def read_word(self):
        """Membaca kata dari socket"""
        length = self.read_length()
        if length == 0:
            return ''
        return self.sock.recv(length).decode('utf-8')
    
    def read_sentence(self):
        """Membaca kalimat dari socket"""
        sentence = []
        while True:
            word = self.read_word()
            if word == '':
                break
            sentence.append(word)
        return sentence
    
    def login(self, username, password):
        """Login ke Mikrotik"""
        try:
            # Untuk RouterOS versi baru (6.43+), langsung kirim username dan password
            self.send_sentence(['/login', f'=name={username}', f'=password={password}'])
            response = self.read_sentence()
            
            # Cek apakah login berhasil
            if len(response) > 0 and response[0] == '!done':
                print("Login berhasil!")
                return True
            elif len(response) > 0 and response[0] == '!trap':
                # Login gagal, tampilkan pesan error
                error_msg = "Login gagal!"
                for word in response:
                    if '=message=' in word:
                        error_msg = word.split('=message=')[1]
                print(f"Login gagal: {error_msg}")
                return False
            else:
                # Coba metode lama dengan challenge (RouterOS < 6.43)
                self.send_sentence(['/login'])
                response = self.read_sentence()
                
                if len(response) > 1 and '=ret=' in response[1]:
                    challenge = response[1].split('=ret=')[1]
                    challenge_bytes = binascii.unhexlify(challenge)
                    
                    # Buat hash MD5 dari password dan challenge
                    md5 = hashlib.md5()
                    md5.update(b'\x00')
                    md5.update(password.encode('utf-8'))
                    md5.update(challenge_bytes)
                    hash_result = binascii.hexlify(md5.digest()).decode('utf-8')
                    
                    # Kirim username dan hash
                    self.send_sentence(['/login', f'=name={username}', f'=response=00{hash_result}'])
                    response = self.read_sentence()
                    
                    if response[0] == '!done':
                        print("Login berhasil!")
                        return True
                
                print("Login gagal!")
                return False
        except Exception as e:
            print(f"Error saat login: {e}")
            return False
    
    def talk(self, command):
        """Mengirim perintah dan menerima respons"""
        if isinstance(command, str):
            command = [command]
        
        self.send_sentence(command)
        response = []
        
        while True:
            sentence = self.read_sentence()
            if len(sentence) == 0:
                break
            
            response.append(sentence)
            
            if sentence[0] == '!done':
                break
        
        return response
    
    def get_interfaces(self):
        """Mengambil daftar interface"""
        response = self.talk('/interface/print')
        interfaces = []
        
        for sentence in response:
            if sentence[0] == '!re':
                interface_data = {}
                for word in sentence:
                    if word.startswith('='):
                        key_value = word[1:].split('=', 1)
                        if len(key_value) == 2:
                            interface_data[key_value[0]] = key_value[1]
                        elif len(key_value) == 1:
                            interface_data[key_value[0]] = ''
                if interface_data:
                    interfaces.append(interface_data)
        
        return interfaces
    
    def rename_interface(self, old_name, new_name):
        """Mengubah nama interface"""
        try:
            interfaces = self.get_interfaces()
            interface_id = None
            
            for iface in interfaces:
                if iface.get('name') == old_name:
                    interface_id = iface.get('.id')
                    break
            
            if not interface_id:
                print(f"Interface '{old_name}' tidak ditemukan")
                return False
            
            command = ['/interface/set', f'=.id={interface_id}', f'=name={new_name}']
            response = self.talk(command)
            
            if response and response[0][0] == '!done':
                print(f"Interface '{old_name}' berhasil diubah menjadi '{new_name}'")
                return True
            else:
                print(f"Gagal mengubah nama interface")
                for sentence in response:
                    for word in sentence:
                        if '=message=' in word:
                            print(f"Error: {word.split('=message=')[1]}")
                return False
                
        except Exception as e:
            print(f"Error saat mengubah nama interface: {e}")
            return False
    
    def set_interface_comment(self, interface_name, comment):
        """Mengubah comment interface"""
        try:
            interfaces = self.get_interfaces()
            interface_id = None
            
            for iface in interfaces:
                if iface.get('name') == interface_name:
                    interface_id = iface.get('.id')
                    break
            
            if not interface_id:
                print(f"Interface '{interface_name}' tidak ditemukan")
                return False
            
            command = ['/interface/set', f'=.id={interface_id}', f'=comment={comment}']
            response = self.talk(command)
            
            if response and response[0][0] == '!done':
                print(f"Comment interface '{interface_name}' berhasil diubah menjadi '{comment}'")
                return True
            else:
                print(f"Gagal mengubah comment interface")
                return False
                
        except Exception as e:
            print(f"Error saat mengubah comment: {e}")
            return False
    
    def enable_disable_interface(self, interface_name, enable=True):
        """Enable atau disable interface"""
        try:
            interfaces = self.get_interfaces()
            interface_id = None
            
            for iface in interfaces:
                if iface.get('name') == interface_name:
                    interface_id = iface.get('.id')
                    break
            
            if not interface_id:
                print(f"Interface '{interface_name}' tidak ditemukan")
                return False
            
            disabled_value = 'no' if enable else 'yes'
            command = ['/interface/set', f'=.id={interface_id}', f'=disabled={disabled_value}']
            response = self.talk(command)
            
            if response and response[0][0] == '!done':
                status = "enabled" if enable else "disabled"
                print(f"Interface '{interface_name}' berhasil {status}")
                return True
            else:
                print(f"Gagal mengubah status interface")
                return False
                
        except Exception as e:
            print(f"Error saat mengubah status interface: {e}")
            return False
    
    def disconnect(self):
        """Memutus koneksi"""
        if self.sock:
            self.sock.close()
            self.connected = False
            print("Koneksi ditutup")

# Contoh penggunaan
if __name__ == "__main__":
    # METODE 1: Koneksi menggunakan MAC Address
    # Ganti dengan MAC address Mikrotik Anda
    MAC_ADDRESS = '00:0C:29:DA:29:27'  # Format bisa AA:BB:CC:DD:EE:FF atau AA-BB-CC-DD-EE-FF
    
    # METODE 2: Koneksi menggunakan IP (cara lama)
    # HOST = '192.168.80.3'
    
    PORT = 8728
    USERNAME = 'admin'
    PASSWORD = 'admin'
    
    # Gunakan MAC address untuk koneksi
    print("=== Koneksi Menggunakan MAC Address ===")
    api = MikrotikAPI(mac_address=MAC_ADDRESS, port=PORT)
    
    # Atau gunakan IP langsung (uncomment baris di bawah)
    # api = MikrotikAPI(host=HOST, port=PORT)
    
    if api.connect():
        if api.login(USERNAME, PASSWORD):
            # Contoh: Mengambil informasi sistem
            # print("\n--- Informasi Sistem ---")
            # response = api.talk('/system/resource/print')
            # for sentence in response:
                # for word in sentence:
                   # print(word)
            
            # Contoh: Mengambil daftar interface
            # print("\n--- Daftar Interface ---")
            # interfaces = api.get_interfaces()
            # for iface in interfaces:
               # name = iface.get('name', 'N/A')
               # iface_type = iface.get('type', 'N/A')
               # mac = iface.get('mac-address', 'N/A')
               # disabled = iface.get('disabled', 'false')
               # status = 'Disabled' if disabled == 'true' else 'Enabled'
               # print(f"- {name} ({iface_type}) - MAC: {mac} - {status}")
            
            # Contoh: Mengubah nama interface
            #print("\n--- Mengubah Nama Interface ---")
            api.rename_interface('ether1', 'ether1')
            
            # Contoh: Mengubah comment
            # api.set_interface_comment('ether1', 'Koneksi Internet')
            
            # Contoh: Enable/Disable interface
            # api.enable_disable_interface('ether5', enable=False)
        
        api.disconnect()