"""
Module de Scan Réseau Avancé
"""

import socket
import subprocess
import platform
import threading
import time
import re
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple
import ipaddress

from modules.config import SERVICE_NAMES, COMMON_PORTS, TOP_PORTS


@dataclass
class PortResult:
    """Résultat du scan d'un port"""
    port: int
    state: str = "closed"  # open, closed, filtered
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class HostResult:
    """Résultat du scan d'un hôte"""
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    is_up: bool = False
    response_time: float = 0.0
    os_guess: str = ""
    os_accuracy: int = 0
    ports: List[PortResult] = field(default_factory=list)
    
    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]
    
    @property
    def open_port_count(self) -> int:
        return len(self.open_ports)


@dataclass
class ScanResult:
    """Résultat complet d'un scan"""
    target: str
    start_time: str
    end_time: str = ""
    duration: float = 0.0
    hosts_scanned: int = 0
    hosts_up: int = 0
    total_open_ports: int = 0
    hosts: List[HostResult] = field(default_factory=list)


class PortScanner:
    """Scanner de ports TCP/UDP"""
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
    
    def tcp_connect(self, ip: str, port: int) -> Tuple[bool, str]:
        """Test de connexion TCP avec récupération de bannière"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            banner = ""
            if result == 0:
                try:
                    # Tenter de récupérer une bannière
                    sock.settimeout(0.5)
                    
                    # Ports qui envoient une bannière automatiquement
                    if port in [21, 22, 25, 110, 143, 220, 993, 995]:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # HTTP
                    elif port in [80, 8080, 8000, 8888, 3000]:
                        sock.send(b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # HTTPS - juste vérifier la connexion
                    elif port in [443, 8443]:
                        banner = "SSL/TLS"
                    
                    # MySQL
                    elif port == 3306:
                        data = sock.recv(1024)
                        if len(data) > 5:
                            version_end = data.find(b'\x00', 5)
                            if version_end > 5:
                                banner = data[5:version_end].decode('utf-8', errors='ignore')
                    
                    # Redis
                    elif port == 6379:
                        sock.send(b'INFO\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                    
                    # MongoDB
                    elif port == 27017:
                        banner = "MongoDB"
                
                except (socket.timeout, socket.error, OSError, UnicodeDecodeError):
                    pass
                
                sock.close()
                return True, banner
            
            sock.close()
            return False, ""
        
        except socket.timeout:
            return False, ""
        except (socket.error, OSError):
            return False, ""
    
    def tcp_syn_scan(self, ip: str, port: int) -> bool:
        """Scan SYN (nécessite root/admin)"""
        # Simplifié - utilise connect scan car SYN nécessite raw sockets
        is_open, _ = self.tcp_connect(ip, port)
        return is_open
    
    def udp_scan(self, ip: str, port: int) -> bool:
        """Scan UDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'\x00', (ip, port))
            
            try:
                sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return True  # Pas de réponse = peut être ouvert
        except (socket.error, OSError):
            return False
    
    def scan_port(self, ip: str, port: int, protocol: str = "tcp") -> PortResult:
        """Scanner un port spécifique"""
        service = SERVICE_NAMES.get(port, "unknown")
        
        if protocol == "tcp":
            is_open, banner = self.tcp_connect(ip, port)
        else:
            is_open = self.udp_scan(ip, port)
            banner = ""
        
        # Extraire la version du banner
        version = ""
        if banner:
            # SSH version
            if "SSH-" in banner:
                version = banner.split('\n')[0]
            # HTTP Server
            elif "Server:" in banner:
                match = re.search(r'Server:\s*(.+)', banner)
                if match:
                    version = match.group(1).strip()
            # Autres
            else:
                version = banner[:50]
        
        return PortResult(
            port=port,
            state="open" if is_open else "closed",
            protocol=protocol,
            service=service,
            banner=banner[:200] if banner else "",
            version=version
        )
    
    def scan_ports(self, ip: str, ports: List[int], 
                   protocol: str = "tcp",
                   callback: Callable = None,
                   max_threads: int = 100) -> List[PortResult]:
        """Scanner plusieurs ports en parallèle"""
        results = []
        total = len(ports)
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port, protocol): port 
                for port in ports
            }
            
            for i, future in enumerate(as_completed(futures)):
                try:
                    result = future.result()
                    if result.state == "open":
                        results.append(result)
                    
                    if callback:
                        callback(i + 1, total, futures[future])
                except Exception:
                    # Une erreur sur un port donné ne doit pas bloquer le scan global
                    pass
        
        return sorted(results, key=lambda x: x.port)


class NetworkScanner:
    """Scanner réseau complet"""
    
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.port_scanner = PortScanner(timeout)
        self.cancel_requested = False
        self._lock = threading.Lock()
    
    def get_local_ip(self) -> str:
        """Obtenir l'IP locale"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except (socket.error, OSError):
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Obtenir la plage réseau"""
        local_ip = self.get_local_ip()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    def get_gateway(self) -> str:
        """Obtenir la passerelle par défaut"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                match = re.search(r'Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
            else:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
        return ""
    
    def ping(self, ip: str) -> Tuple[bool, float]:
        """Ping un hôte"""
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
        timeout_val = str(int(self.timeout * 1000)) if platform.system().lower() == 'windows' else str(int(self.timeout))
        
        try:
            start = time.time()
            result = subprocess.run(
                ['ping', param, '1', timeout_param, timeout_val, ip],
                capture_output=True,
                text=True,
                timeout=self.timeout + 2
            )
            elapsed = (time.time() - start) * 1000
            
            if result.returncode == 0:
                # Extraire le temps de réponse
                time_match = re.search(r'time[=<](\d+\.?\d*)', result.stdout)
                if time_match:
                    return True, float(time_match.group(1))
                return True, elapsed
            return False, 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False, 0
    
    def arp_scan(self, ip: str) -> str:
        """Récupérer l'adresse MAC via ARP"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                match = re.search(r'([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', result.stdout)
            
            if match:
                return match.group(0).upper()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass
        return ""

    def resolve_hostname(self, ip: str) -> str:
        """Résolution DNS inverse"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""
    
    def detect_os(self, ports: List[PortResult], ttl: int = 0) -> Tuple[str, int]:
        """Détecter l'OS basé sur les ports ouverts et TTL"""
        port_numbers = {p.port for p in ports}
        score = 0
        os_name = "Unknown"
        
        # Ports Windows
        windows_ports = {135, 139, 445, 3389, 1433, 5985}
        # Ports Linux
        linux_ports = {22, 111, 2049, 3306, 5432}
        # Ports macOS
        macos_ports = {22, 548, 5900, 3283}
        
        windows_score = len(port_numbers & windows_ports)
        linux_score = len(port_numbers & linux_ports)
        macos_score = len(port_numbers & macos_ports)
        
        if windows_score > linux_score and windows_score > macos_score:
            os_name = "Windows"
            score = min(95, 50 + windows_score * 15)
        elif linux_score > windows_score:
            os_name = "Linux/Unix"
            score = min(90, 50 + linux_score * 15)
        elif macos_score > 0:
            os_name = "macOS"
            score = min(85, 50 + macos_score * 15)
        
        # Vérification par bannière
        for port in ports:
            if port.banner:
                banner_lower = port.banner.lower()
                if 'windows' in banner_lower or 'microsoft' in banner_lower:
                    os_name = "Windows"
                    score = max(score, 80)
                elif 'ubuntu' in banner_lower or 'debian' in banner_lower:
                    os_name = "Linux (Debian/Ubuntu)"
                    score = max(score, 85)
                elif 'centos' in banner_lower or 'red hat' in banner_lower:
                    os_name = "Linux (RHEL/CentOS)"
                    score = max(score, 85)
                elif 'apache' in banner_lower:
                    if os_name == "Unknown":
                        os_name = "Linux (Apache)"
                        score = 60
                elif 'nginx' in banner_lower:
                    if os_name == "Unknown":
                        os_name = "Linux (Nginx)"
                        score = 60
                elif 'iis' in banner_lower:
                    os_name = "Windows (IIS)"
                    score = max(score, 85)
        
        return os_name, score
    
    def scan_host(self, ip: str, ports: List[int] = None, 
                  full_scan: bool = False) -> HostResult:
        """Scanner un hôte complet"""
        if self.cancel_requested:
            return HostResult(ip=ip, is_up=False)
        
        if ports is None:
            ports = TOP_PORTS if not full_scan else COMMON_PORTS
        
        # Vérifier si l'hôte est up
        is_up, response_time = self.ping(ip)
        
        # Si pas de réponse ping, tester quelques ports
        if not is_up:
            for test_port in [80, 443, 22, 445, 3389]:
                is_open, _ = self.port_scanner.tcp_connect(ip, test_port)
                if is_open:
                    is_up = True
                    break
        
        if not is_up:
            return HostResult(ip=ip, is_up=False)
        
        # Scanner les ports
        open_ports = self.port_scanner.scan_ports(ip, ports)
        
        # Infos supplémentaires
        hostname = self.resolve_hostname(ip)
        mac = self.arp_scan(ip)
        os_name, os_accuracy = self.detect_os(open_ports)
        
        return HostResult(
            ip=ip,
            hostname=hostname,
            mac=mac,
            is_up=True,
            response_time=response_time,
            os_guess=os_name,
            os_accuracy=os_accuracy,
            ports=open_ports
        )
    
    def scan_network(self, target: str, ports: List[int] = None,
                     callback: Callable = None,
                     max_threads: int = 50,
                     full_scan: bool = False) -> ScanResult:
        """Scanner un réseau complet"""
        from datetime import datetime
        
        self.cancel_requested = False
        start_time = datetime.now()
        
        # Parser la cible
        ips = self._parse_target(target)
        if not ips:
            return ScanResult(
                target=target,
                start_time=start_time.isoformat(),
                end_time=datetime.now().isoformat()
            )
        
        total = len(ips)
        hosts = []
        hosts_up = 0
        
        # Scanner en parallèle
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self.scan_host, ip, ports, full_scan): ip 
                for ip in ips
            }
            
            for i, future in enumerate(as_completed(futures)):
                if self.cancel_requested:
                    break
                
                ip = futures[future]
                try:
                    result = future.result()
                    if result.is_up:
                        hosts.append(result)
                        hosts_up += 1
                    
                    if callback:
                        percent = int((i + 1) / total * 100)
                        callback(i + 1, total, ip, percent, result)
                except Exception as e:
                    if callback:
                        callback(i + 1, total, ip, int((i + 1) / total * 100), None)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Calculer le total de ports ouverts
        total_open = sum(len(h.open_ports) for h in hosts)
        
        return ScanResult(
            target=target,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration=duration,
            hosts_scanned=total,
            hosts_up=hosts_up,
            total_open_ports=total_open,
            hosts=sorted(hosts, key=lambda x: socket.inet_aton(x.ip))
        )
    
    def _parse_target(self, target: str) -> List[str]:
        """Parser une cible en liste d'IPs"""
        ips = []
        
        try:
            target = target.strip()
            
            # CIDR notation
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            
            # Range: 192.168.1.1-254 ou 192.168.1.1-192.168.1.254
            elif '-' in target:
                if target.count('.') == 3 and '-' in target.split('.')[-1]:
                    # 192.168.1.1-254
                    base = '.'.join(target.split('.')[:-1])
                    range_part = target.split('.')[-1]
                    start_s, end_s = range_part.split('-')
                    start, end = int(start_s.strip()), int(end_s.strip())
                    if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
                        raise ValueError(f"Octet hors plage 0-255 ou inversé: {start}-{end}")
                    # Valide que la base est un préfixe IPv4 correct
                    ipaddress.IPv4Address(f"{base}.{start}")
                    ips = [f"{base}.{i}" for i in range(start, end + 1)]
                else:
                    # 192.168.1.1-192.168.1.254
                    start_ip, end_ip = target.split('-')
                    start = ipaddress.IPv4Address(start_ip.strip())
                    end = ipaddress.IPv4Address(end_ip.strip())
                    if int(start) > int(end):
                        raise ValueError("Plage IP inversée")
                    ips = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
            
            # Single IP or hostname
            else:
                try:
                    # Tenter de résoudre si c'est un hostname
                    ipaddress.ip_address(target)
                    ips = [target]
                except ValueError:
                    # C'est un hostname
                    try:
                        resolved = socket.gethostbyname(target)
                        ips = [resolved]
                    except socket.gaierror:
                        pass
        
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            print(f"Erreur parsing target '{target}': {e}")
        except Exception as e:
            print(f"Erreur parsing target: {e}")
        
        # Limiter à 1024 IPs
        return ips[:1024]
    
    def cancel(self):
        """Annuler le scan"""
        with self._lock:
            self.cancel_requested = True


class ServiceDetector:
    """Détection avancée de services"""
    
    @staticmethod
    def detect_http_info(ip: str, port: int = 80, timeout: float = 2.0) -> Dict:
        """Détecter les infos d'un serveur HTTP"""
        info = {
            "server": "",
            "title": "",
            "technologies": [],
            "headers": {}
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except (socket.timeout, socket.error, OSError):
                    break
            
            sock.close()
            response_str = response.decode('utf-8', errors='ignore')
            
            # Parser les headers
            if '\r\n\r\n' in response_str:
                headers_part = response_str.split('\r\n\r\n')[0]
                for line in headers_part.split('\r\n')[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info['headers'][key.strip()] = value.strip()
            
            # Serveur
            info['server'] = info['headers'].get('Server', '')
            
            # Titre de la page
            title_match = re.search(r'<title>([^<]+)</title>', response_str, re.IGNORECASE)
            if title_match:
                info['title'] = title_match.group(1).strip()
            
            # Technologies détectées
            techs = []
            response_lower = response_str.lower()
            
            if 'wordpress' in response_lower or 'wp-content' in response_lower:
                techs.append("WordPress")
            if 'drupal' in response_lower:
                techs.append("Drupal")
            if 'joomla' in response_lower:
                techs.append("Joomla")
            if 'laravel' in response_lower:
                techs.append("Laravel")
            if 'django' in response_lower:
                techs.append("Django")
            if 'react' in response_lower:
                techs.append("React")
            if 'angular' in response_lower:
                techs.append("Angular")
            if 'vue' in response_lower:
                techs.append("Vue.js")
            if 'jquery' in response_lower:
                techs.append("jQuery")
            if 'bootstrap' in response_lower:
                techs.append("Bootstrap")
            if 'php' in info['headers'].get('X-Powered-By', '').lower():
                techs.append("PHP")
            if 'asp.net' in info['headers'].get('X-Powered-By', '').lower():
                techs.append("ASP.NET")
            
            info['technologies'] = techs
        
        except (socket.timeout, socket.error, OSError, UnicodeDecodeError):
            pass
        
        return info
    
    @staticmethod
    def detect_ssl_info(ip: str, port: int = 443, timeout: float = 3.0) -> Dict:
        """Détecter les infos SSL/TLS"""
        info = {
            "valid": False,
            "issuer": "",
            "subject": "",
            "expires": "",
            "protocol": ""
        }
        
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        info['valid'] = True
                        info['subject'] = str(cert.get('subject', ''))
                        info['issuer'] = str(cert.get('issuer', ''))
                        info['expires'] = cert.get('notAfter', '')
                    info['protocol'] = ssock.version()
        except Exception:
            # ssl.SSLError, socket errors, etc. — multiples causes possibles
            pass
        
        return info


# ============================================================
# INTÉGRATION NMAP
# ============================================================

class NmapScanner:
    """
    Scanner utilisant Nmap via python-nmap
    Nécessite: pip install python-nmap
    Et Nmap installé sur le système
    """
    
    def __init__(self):
        self.nm = None
        self.available = False
        self._check_nmap()
    
    def _check_nmap(self):
        """Vérifier si Nmap est disponible"""
        try:
            import nmap
            self.nm = nmap.PortScanner()
            # Test rapide
            self.nm.scan('127.0.0.1', '22', arguments='-sn')
            self.available = True
        except ImportError:
            print("python-nmap non installé. Utilisez: pip install python-nmap")
            self.available = False
        except Exception as e:
            print(f"Nmap non disponible: {e}")
            self.available = False
    
    def is_available(self) -> bool:
        """Vérifier si Nmap est disponible"""
        return self.available
    
    def quick_scan(self, target: str, callback: Callable = None) -> ScanResult:
        """
        Scan rapide (-T4 -F)
        Scanne les 100 ports les plus courants
        """
        return self._run_scan(target, '-T4 -F', callback)
    
    def full_scan(self, target: str, callback: Callable = None) -> ScanResult:
        """
        Scan complet (-T4 -A -p-)
        Tous les ports + détection OS/version
        """
        return self._run_scan(target, '-T4 -A -p-', callback)
    
    def stealth_scan(self, target: str, callback: Callable = None) -> ScanResult:
        """
        Scan furtif SYN (-sS)
        Nécessite des privilèges root/admin
        """
        return self._run_scan(target, '-sS -T4', callback)
    
    def vuln_scan(self, target: str, callback: Callable = None) -> ScanResult:
        """
        Scan de vulnérabilités avec scripts NSE
        """
        return self._run_scan(target, '-sV --script=vuln', callback)
    
    def service_scan(self, target: str, ports: str = None, callback: Callable = None) -> ScanResult:
        """
        Scan de services avec détection de version (-sV)
        """
        port_arg = f'-p {ports}' if ports else '-F'
        return self._run_scan(target, f'-sV -T4 {port_arg}', callback)
    
    def os_detection(self, target: str, callback: Callable = None) -> ScanResult:
        """
        Détection d'OS (-O)
        Nécessite des privilèges root/admin
        """
        return self._run_scan(target, '-O -T4', callback)
    
    def custom_scan(self, target: str, arguments: str, callback: Callable = None) -> ScanResult:
        """
        Scan personnalisé avec arguments Nmap
        """
        return self._run_scan(target, arguments, callback)
    
    def _run_scan(self, target: str, arguments: str, callback: Callable = None) -> ScanResult:
        """Exécuter un scan Nmap"""
        if not self.available:
            return ScanResult(
                target=target,
                start_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                end_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
        
        from datetime import datetime
        start = datetime.now()
        
        result = ScanResult(
            target=target,
            start_time=start.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        try:
            if callback:
                callback(f"Démarrage scan Nmap: {target}")
                callback(f"Arguments: {arguments}")
            
            # Lancer le scan
            self.nm.scan(hosts=target, arguments=arguments)
            
            # Parser les résultats
            for host in self.nm.all_hosts():
                host_result = HostResult(ip=host)
                
                # Hostname
                if 'hostnames' in self.nm[host]:
                    names = self.nm[host]['hostnames']
                    if names and len(names) > 0:
                        host_result.hostname = names[0].get('name', '')
                
                # État
                if self.nm[host].state() == 'up':
                    host_result.is_up = True
                    result.hosts_up += 1
                
                # MAC Address
                if 'addresses' in self.nm[host]:
                    addresses = self.nm[host]['addresses']
                    if 'mac' in addresses:
                        host_result.mac = addresses['mac']
                
                # OS Detection
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        host_result.os_guess = best_match.get('name', '')
                        host_result.os_accuracy = int(best_match.get('accuracy', 0))
                
                # Ports TCP
                if 'tcp' in self.nm[host]:
                    for port, port_data in self.nm[host]['tcp'].items():
                        port_result = PortResult(
                            port=port,
                            state=port_data.get('state', 'unknown'),
                            protocol='tcp',
                            service=port_data.get('name', ''),
                            version=port_data.get('version', ''),
                            banner=port_data.get('product', '')
                        )
                        host_result.ports.append(port_result)
                        if port_result.state == 'open':
                            result.total_open_ports += 1
                
                # Ports UDP
                if 'udp' in self.nm[host]:
                    for port, port_data in self.nm[host]['udp'].items():
                        port_result = PortResult(
                            port=port,
                            state=port_data.get('state', 'unknown'),
                            protocol='udp',
                            service=port_data.get('name', ''),
                            version=port_data.get('version', '')
                        )
                        host_result.ports.append(port_result)
                        if port_result.state == 'open':
                            result.total_open_ports += 1
                
                result.hosts.append(host_result)
                result.hosts_scanned += 1
                
                if callback:
                    callback(f"Hôte scanné: {host} ({host_result.open_port_count} ports ouverts)")
        
        except Exception as e:
            if callback:
                callback(f"Erreur Nmap: {str(e)}")
        
        end = datetime.now()
        result.end_time = end.strftime('%Y-%m-%d %H:%M:%S')
        result.duration = (end - start).total_seconds()
        
        if callback:
            callback(f"Scan terminé en {result.duration:.1f}s")
        
        return result
    
    def get_nmap_version(self) -> str:
        """Obtenir la version de Nmap"""
        if not self.available:
            return "Non disponible"
        try:
            return self.nm.nmap_version()[0]
        except (AttributeError, IndexError, Exception):
            return "Inconnu"
    
    def get_scan_types(self) -> List[Dict]:
        """Liste des types de scan disponibles"""
        return [
            {
                'id': 'quick',
                'name': 'Scan Rapide',
                'description': 'Top 100 ports (-T4 -F)',
                'requires_root': False
            },
            {
                'id': 'full',
                'name': 'Scan Complet',
                'description': 'Tous les ports + OS/Version (-T4 -A -p-)',
                'requires_root': False
            },
            {
                'id': 'stealth',
                'name': 'Scan Furtif (SYN)',
                'description': 'Scan TCP SYN (-sS)',
                'requires_root': True
            },
            {
                'id': 'service',
                'name': 'Détection Services',
                'description': 'Version des services (-sV)',
                'requires_root': False
            },
            {
                'id': 'vuln',
                'name': 'Scan Vulnérabilités',
                'description': 'Scripts NSE vulnérabilités (--script=vuln)',
                'requires_root': False
            },
            {
                'id': 'os',
                'name': 'Détection OS',
                'description': 'Fingerprinting OS (-O)',
                'requires_root': True
            }
        ]


# Instance globale Nmap
nmap_scanner = NmapScanner()
