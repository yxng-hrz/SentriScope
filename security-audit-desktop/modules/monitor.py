"""Module de Monitoring Système et Réseau"""
import psutil, socket, threading, time, platform, re
from datetime import datetime
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional


@dataclass
class NetworkStats:
    timestamp: str
    bytes_sent: int = 0; bytes_recv: int = 0
    bytes_sent_rate: float = 0.0; bytes_recv_rate: float = 0.0
    packets_sent: int = 0; packets_recv: int = 0
    packets_sent_rate: float = 0.0; packets_recv_rate: float = 0.0
    errors_in: int = 0; errors_out: int = 0
    drops_in: int = 0; drops_out: int = 0


@dataclass
class ConnectionInfo:
    protocol: str; local_ip: str; local_port: int
    remote_ip: str; remote_port: int; status: str
    pid: int; process: str
    def to_dict(self) -> Dict:
        return {k: getattr(self, k) for k in
                ('protocol','local_ip','local_port','remote_ip','remote_port','status','pid','process')}


@dataclass
class ProcessInfo:
    pid: int; name: str; username: str; cpu_percent: float
    memory_percent: float; memory_mb: float; status: str
    connections: int; threads: int; created: str


class NetworkMonitor:
    def __init__(self, history_size: int = 300):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: List[Callable] = []
        self._history: deque = deque(maxlen=history_size)
        self._last_io = None; self._last_time = None
        self._lock = threading.Lock()

    def add_callback(self, cb):
        with self._lock:
            if cb not in self._callbacks: self._callbacks.append(cb)

    def remove_callback(self, cb):
        with self._lock:
            if cb in self._callbacks: self._callbacks.remove(cb)

    def start(self, interval: float = 1.0):
        if self.is_running: return
        self.is_running = True
        self._last_io = psutil.net_io_counters()
        self._last_time = time.time()
        self._thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False
        if self._thread: self._thread.join(timeout=2)

    def _loop(self, interval):
        while self.is_running:
            try:
                cur = psutil.net_io_counters()
                now = time.time()
                dt = now - self._last_time
                if dt > 0:
                    stats = NetworkStats(
                        timestamp=datetime.now().strftime('%H:%M:%S'),
                        bytes_sent=cur.bytes_sent, bytes_recv=cur.bytes_recv,
                        bytes_sent_rate=(cur.bytes_sent - self._last_io.bytes_sent) / dt,
                        bytes_recv_rate=(cur.bytes_recv - self._last_io.bytes_recv) / dt,
                        packets_sent=cur.packets_sent, packets_recv=cur.packets_recv,
                        packets_sent_rate=(cur.packets_sent - self._last_io.packets_sent) / dt,
                        packets_recv_rate=(cur.packets_recv - self._last_io.packets_recv) / dt,
                        errors_in=cur.errin, errors_out=cur.errout,
                        drops_in=cur.dropin, drops_out=cur.dropout)
                    self._last_io, self._last_time = cur, now
                    self._history.append(stats)
                    with self._lock:
                        for cb in self._callbacks:
                            try: cb(stats)
                            except: pass
                time.sleep(interval)
            except Exception:
                time.sleep(interval)

    def get_history(self, count=None):
        return list(self._history)[-count:] if count else list(self._history)

    def get_current_stats(self):
        return self._history[-1] if self._history else None


class ConnectionMonitor:
    @staticmethod
    def get_connections(include_localhost=False) -> List[ConnectionInfo]:
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if not c.laddr: continue
                if not include_localhost and c.laddr.ip in ('127.0.0.1', '::1', '0.0.0.0'): continue
                pname = ""
                if c.pid:
                    try: pname = psutil.Process(c.pid).name()
                    except: pass
                conns.append(ConnectionInfo(
                    protocol='TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                    local_ip=c.laddr.ip, local_port=c.laddr.port,
                    remote_ip=c.raddr.ip if c.raddr else '*',
                    remote_port=c.raddr.port if c.raddr else 0,
                    status=c.status if hasattr(c, 'status') else 'NONE',
                    pid=c.pid or 0, process=pname))
        except (psutil.AccessDenied, PermissionError): pass
        return conns

    @staticmethod
    def get_listening_ports():
        return [c for c in ConnectionMonitor.get_connections(True) if c.status == 'LISTEN']

    @staticmethod
    def get_established_connections():
        return [c for c in ConnectionMonitor.get_connections() if c.status == 'ESTABLISHED']

    @staticmethod
    def get_connections_by_process() -> Dict[str, List]:
        by_proc = {}
        for c in ConnectionMonitor.get_connections(True):
            k = c.process or f"PID:{c.pid}"
            by_proc.setdefault(k, []).append(c)
        return by_proc

    @staticmethod
    def get_connection_stats() -> Dict:
        conns = ConnectionMonitor.get_connections(True)
        s = {'total': len(conns), 'tcp': 0, 'udp': 0, 'established': 0,
             'listening': 0, 'time_wait': 0, 'close_wait': 0, 'by_status': {},
             'unique_remote_ips': set(), 'unique_local_ports': set()}
        for c in conns:
            s['tcp' if c.protocol == 'TCP' else 'udp'] += 1
            for st in ('established', 'listening', 'time_wait', 'close_wait'):
                if c.status.lower().replace('_', '') == st.replace('_', ''):
                    s[st] += 1
            s['by_status'][c.status] = s['by_status'].get(c.status, 0) + 1
            if c.remote_ip and c.remote_ip != '*': s['unique_remote_ips'].add(c.remote_ip)
            s['unique_local_ports'].add(c.local_port)
        s['unique_remote_ips'] = len(s['unique_remote_ips'])
        s['unique_local_ports'] = len(s['unique_local_ports'])
        return s


class SystemMonitor:
    @staticmethod
    def get_cpu_info() -> Dict:
        freq = psutil.cpu_freq()
        return {
            'percent': psutil.cpu_percent(interval=0.1),
            'percent_per_core': psutil.cpu_percent(interval=0.1, percpu=True),
            'count_logical': psutil.cpu_count(True), 'count_physical': psutil.cpu_count(False),
            'freq_current': freq.current if freq else 0, 'freq_max': freq.max if freq else 0,
            'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0,0,0)}

    @staticmethod
    def get_memory_info() -> Dict:
        m, s = psutil.virtual_memory(), psutil.swap_memory()
        return {'total': m.total, 'used': m.used, 'available': m.available,
                'percent': m.percent, 'swap_total': s.total,
                'swap_used': s.used, 'swap_percent': s.percent}

    @staticmethod
    def get_disk_info() -> Dict:
        d = psutil.disk_usage('/')
        io = psutil.disk_io_counters()
        return {'total': d.total, 'used': d.used, 'free': d.free, 'percent': d.percent,
                'read_bytes': io.read_bytes if io else 0, 'write_bytes': io.write_bytes if io else 0}

    @staticmethod
    def get_system_info() -> Dict:
        bt = datetime.fromtimestamp(psutil.boot_time())
        up = datetime.now() - bt
        days = up.days
        hours = up.seconds // 3600
        minutes = (up.seconds % 3600) // 60
        return {
            'hostname': socket.gethostname(), 'platform': platform.system(),
            'platform_release': platform.release(), 'platform_version': platform.version(),
            'architecture': platform.machine(), 'processor': platform.processor(),
            'boot_time': bt.strftime('%Y-%m-%d %H:%M:%S'),
            'uptime': f"{days}j {hours}h {minutes}m",
            'python_version': platform.python_version()}


class ProcessMonitor:
    @staticmethod
    def get_processes(sort_by='cpu', limit=50, interval=0.0) -> List[ProcessInfo]:
        """Get processes. Set interval>0 for accurate CPU measurement."""
        procs = list(psutil.process_iter(['pid','name','username','memory_percent',
                                          'memory_info','status','num_threads','create_time']))
        if interval > 0:
            for p in procs:
                try: p.cpu_percent()
                except: pass
            time.sleep(interval)

        results = []
        for p in procs:
            try:
                i = p.info if interval == 0 else p.as_dict(
                    ['pid','name','username','memory_percent','memory_info','status','num_threads','create_time'])
                cpu = p.cpu_percent(interval=0) if interval == 0 else p.cpu_percent()
                try: conns = len(p.connections())
                except: conns = 0
                mem_mb = i['memory_info'].rss / 1048576 if i['memory_info'] else 0
                ct = datetime.fromtimestamp(i['create_time']).strftime('%H:%M:%S') if i['create_time'] else ''
                results.append(ProcessInfo(
                    pid=i['pid'], name=i['name'] or 'Unknown', username=i['username'] or 'Unknown',
                    cpu_percent=cpu, memory_percent=i['memory_percent'] or 0, memory_mb=mem_mb,
                    status=i['status'] or 'Unknown', connections=conns,
                    threads=i['num_threads'] or 0, created=ct))
            except: continue

        key = {'cpu': lambda x: x.cpu_percent, 'memory': lambda x: x.memory_percent,
               'connections': lambda x: x.connections, 'name': lambda x: x.name.lower()}
        rev = sort_by != 'name'
        results.sort(key=key.get(sort_by, key['cpu']), reverse=rev)
        return results[:limit]

    # Backward compatibility alias
    @staticmethod
    def get_processes_with_interval(sort_by='cpu', limit=50, interval=0.1):
        return ProcessMonitor.get_processes(sort_by, limit, interval)

    @staticmethod
    def get_network_processes():
        return [p for p in ProcessMonitor.get_processes(sort_by='connections', limit=100) if p.connections > 0]

    @staticmethod
    def kill_process(pid: int) -> bool:
        try: psutil.Process(pid).terminate(); return True
        except: return False


class InterfaceMonitor:
    @staticmethod
    def get_interfaces() -> List[Dict]:
        interfaces = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        io = psutil.net_io_counters(pernic=True)
        for name, st in stats.items():
            iface = {'name': name, 'is_up': st.isup, 'speed': st.speed, 'mtu': st.mtu,
                     'duplex': str(st.duplex) if hasattr(st, 'duplex') else 'Unknown',
                     'ipv4': '', 'ipv6': '', 'mac': '', 'netmask': '',
                     'bytes_sent': 0, 'bytes_recv': 0}
            if name in addrs:
                for a in addrs[name]:
                    if a.family.name == 'AF_INET':
                        iface['ipv4'], iface['netmask'] = a.address, a.netmask
                    elif a.family.name == 'AF_INET6':
                        iface['ipv6'] = a.address
                    elif a.family.name == 'AF_PACKET' or a.family.value == 17:
                        iface['mac'] = a.address
            if name in io:
                iface['bytes_sent'] = io[name].bytes_sent
                iface['bytes_recv'] = io[name].bytes_recv
            interfaces.append(iface)
        return interfaces

    @staticmethod
    def get_default_interface() -> Optional[Dict]:
        for i in InterfaceMonitor.get_interfaces():
            if i['is_up'] and i['ipv4'] and not i['ipv4'].startswith('127.'):
                return i
        return None
