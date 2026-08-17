"""
Module de Géolocalisation IP - SENTRISCOPE
ip-api.com
"""

import ipaddress
import threading
import time
from typing import Dict, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

try:
    import urllib.request
    import json as _json
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


# ─────────────────────────────────────────────
# Drapeaux emoji par code pays (top 60 pays)
# ─────────────────────────────────────────────
COUNTRY_FLAGS = {
    "FR": "🇫🇷", "US": "🇺🇸", "DE": "🇩🇪", "GB": "🇬🇧", "CN": "🇨🇳",
    "RU": "🇷🇺", "JP": "🇯🇵", "KR": "🇰🇷", "IN": "🇮🇳", "BR": "🇧🇷",
    "CA": "🇨🇦", "AU": "🇦🇺", "NL": "🇳🇱", "SE": "🇸🇪", "NO": "🇳🇴",
    "FI": "🇫🇮", "DK": "🇩🇰", "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸",
    "PL": "🇵🇱", "UA": "🇺🇦", "SG": "🇸🇬", "HK": "🇭🇰", "TW": "🇹🇼",
    "TR": "🇹🇷", "IR": "🇮🇷", "SA": "🇸🇦", "ZA": "🇿🇦", "MX": "🇲🇽",
    "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "PT": "🇵🇹", "BE": "🇧🇪",
    "AT": "🇦🇹", "CZ": "🇨🇿", "RO": "🇷🇴", "HU": "🇭🇺", "GR": "🇬🇷",
    "IL": "🇮🇱", "TH": "🇹🇭", "ID": "🇮🇩", "MY": "🇲🇾", "PH": "🇵🇭",
    "VN": "🇻🇳", "PK": "🇵🇰", "BD": "🇧🇩", "NG": "🇳🇬", "EG": "🇪🇬",
    "NZ": "🇳🇿", "LU": "🇱🇺", "IE": "🇮🇪", "SK": "🇸🇰", "HR": "🇭🇷",
    "BG": "🇧🇬", "LT": "🇱🇹", "LV": "🇱🇻", "EE": "🇪🇪", "RS": "🇷🇸",
}

SUSPICIOUS_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "LY"}


@dataclass
class GeoResult:
    ip: str
    status: str = "unknown"
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    lat: float = 0.0
    lon: float = 0.0
    is_private: bool = False
    is_suspicious: bool = False
    cached_at: str = ""

    @property
    def flag(self) -> str:
        return COUNTRY_FLAGS.get(self.country_code, "🌐")

    @property
    def location_str(self) -> str:
        if self.is_private:
            return "🏠 Réseau local"
        if self.status != "success":
            return "❓ Inconnu"
        parts = [p for p in [self.city, self.country] if p]
        return f"{self.flag} {', '.join(parts)}" if parts else f"{self.flag} {self.country_code}"

    @property
    def isp_str(self) -> str:
        return self.isp or self.org or "—"

    @property
    def asn_str(self) -> str:
        return self.asn or "—"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "lat": self.lat,
            "lon": self.lon,
            "is_private": self.is_private,
            "is_suspicious": self.is_suspicious,
            "location": self.location_str,
        }


class GeoIPService:
    """
    Service de géolocalisation IP avec cache TTL.
    Thread-safe. Utilise ip-api.com (batch jusqu'à 100 IPs/requête).
    """

    API_URL      = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon"
    BATCH_URL    = "http://ip-api.com/batch?fields=query,status,country,countryCode,regionName,city,isp,org,as,lat,lon"
    CACHE_TTL    = 3600   # 1 heure
    BATCH_SIZE   = 100    # max par requête batch
    TIMEOUT      = 5      # secondes

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self._cache: Dict[str, GeoResult] = {}
        self._lock = threading.Lock()

    # ── Helpers ──────────────────────────────

    @staticmethod
    def is_private(ip: str) -> bool:
        """Vrai si l'IP est privée / loopback / link-local"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified
        except ValueError:
            return False

    def _private_result(self, ip: str) -> GeoResult:
        return GeoResult(ip=ip, status="private", is_private=True,
                         cached_at=datetime.now().isoformat())

    def _fail_result(self, ip: str) -> GeoResult:
        return GeoResult(ip=ip, status="fail",
                         cached_at=datetime.now().isoformat())

    def _is_cache_valid(self, result: GeoResult) -> bool:
        try:
            cached = datetime.fromisoformat(result.cached_at)
            return (datetime.now() - cached) < timedelta(seconds=self.CACHE_TTL)
        except Exception:
            return False

    def _parse_api_response(self, ip: str, data: dict) -> GeoResult:
        country_code = data.get("countryCode", "")
        return GeoResult(
            ip=ip,
            status=data.get("status", "fail"),
            country=data.get("country", ""),
            country_code=country_code,
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            asn=data.get("as", ""),
            lat=float(data.get("lat", 0)),
            lon=float(data.get("lon", 0)),
            is_private=False,
            is_suspicious=country_code in SUSPICIOUS_COUNTRIES,
            cached_at=datetime.now().isoformat(),
        )

    # ── API calls (synchrones) ────────────────

    def _fetch_single(self, ip: str) -> GeoResult:
        try:
            url = self.API_URL.format(ip=ip)
            req = urllib.request.Request(url, headers={"User-Agent": "SENTRISCOPE/2.2"})
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data = _json.loads(resp.read().decode())
            return self._parse_api_response(ip, data)
        except Exception:
            return self._fail_result(ip)

    def _fetch_batch(self, ips: List[str]) -> Dict[str, GeoResult]:
        results = {}
        try:
            payload = _json.dumps([{"query": ip} for ip in ips]).encode()
            req = urllib.request.Request(
                self.BATCH_URL, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": "SENTRISCOPE/2.2"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                data_list = _json.loads(resp.read().decode())
            for item in data_list:
                ip = item.get("query", "")
                results[ip] = self._parse_api_response(ip, item)
        except Exception:
            for ip in ips:
                results[ip] = self._fail_result(ip)
        return results

    # ── API publique ──────────────────────────

    def lookup(self, ip: str) -> GeoResult:
        """Géolocaliser une seule IP (avec cache)."""
        if self.is_private(ip):
            return self._private_result(ip)

        with self._lock:
            cached = self._cache.get(ip)
            if cached and self._is_cache_valid(cached):
                return cached

        result = self._fetch_single(ip)

        with self._lock:
            self._cache[ip] = result

        return result

    def lookup_many(self, ips: List[str],
                    callback: Optional[Callable[[str, GeoResult], None]] = None
                    ) -> Dict[str, GeoResult]:
        """
        Géolocaliser une liste d'IPs (batch, avec cache).
        Si `callback` est fourni, il est appelé pour chaque IP au fur et à mesure.
        """
        results: Dict[str, GeoResult] = {}
        to_fetch: List[str] = []

        for ip in ips:
            if self.is_private(ip):
                r = self._private_result(ip)
                results[ip] = r
                if callback:
                    callback(ip, r)
                continue

            with self._lock:
                cached = self._cache.get(ip)
            if cached and self._is_cache_valid(cached):
                results[ip] = cached
                if callback:
                    callback(ip, cached)
            else:
                to_fetch.append(ip)

        # Batch fetch par tranches de BATCH_SIZE
        for i in range(0, len(to_fetch), self.BATCH_SIZE):
            chunk = to_fetch[i:i + self.BATCH_SIZE]
            fetched = self._fetch_batch(chunk)
            with self._lock:
                self._cache.update(fetched)
            results.update(fetched)
            if callback:
                for ip, r in fetched.items():
                    callback(ip, r)
            if len(to_fetch) > self.BATCH_SIZE:
                time.sleep(0.15)   # respecter la rate limit

        return results

    def lookup_async(self, ips: List[str],
                     on_result: Callable[[str, GeoResult], None],
                     on_done: Optional[Callable[[], None]] = None):
        """Lance lookup_many dans un thread séparé."""
        def _run():
            self.lookup_many(ips, callback=on_result)
            if on_done:
                on_done()

        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def clear_cache(self):
        with self._lock:
            self._cache.clear()

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)


# Singleton global
geo_ip = GeoIPService()
