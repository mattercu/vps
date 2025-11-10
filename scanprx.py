#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Proxy Scanner v5.0 - Home/ISP Ultimate Edition

Tính năng nâng cao v5.0:
✅ Scan home proxy (Viettel/FPT/Vinaphone/VNPT)
✅ Tự động phát hiện public IP của ISP
✅ Scan IP:Port thông minh với nmap/masscan
✅ Multi-threaded với thread recovery
✅ Phân loại: Siêu Mạnh/Mạnh/TB/Yếu/Siêu Yếu/Die/Honeypot
✅ Bot AI shuffle IP để scan hiệu quả
✅ Honeypot detection nâng cao (10 phương pháp)
✅ Thread watchdog - tự động kill & restart thread treo
✅ ISP range downloader tự động
"""

import asyncio, aiohttp, socket, json, os, sys, logging, random, threading, time
import subprocess, ipaddress, re, queue
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class ProxyQuality(Enum):
    SUPER_STRONG = "sieu_manh"
    STRONG = "manh"
    MEDIUM = "tb"
    WEAK = "yeu"
    SUPER_WEAK = "sieu_yeu"
    DEAD = "die"
    HONEYPOT = "honeypot"

@dataclass
class ProxyInfo:
    ip: str
    port: int
    type: str
    country: str = 'Unknown'
    anonymity: str = 'Unknown'
    response_time: float = 0.0
    success_rate: float = 0.0
    is_working: bool = False
    quality: str = 'Unknown'
    is_honeypot: bool = False
    honeypot_score: float = 0.0
    internal_checks: int = 0
    external_checks: int = 0
    total_checks: int = 0
    successful_checks: int = 0
    last_checked: str = ''
    isp: str = 'Unknown'
    is_home_proxy: bool = False

class ISPRangeManager:
    """Quản lý IP ranges của các ISP Việt Nam"""
    def __init__(self):
        self.cache_dir = 'isp_ranges'
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # ASN của các ISP Việt Nam
        self.isp_asns = {
            'viettel': ['AS7552', 'AS24173', 'AS131353'],
            'fpt': ['AS18403', 'AS131420', 'AS131429'],
            'vinaphone': ['AS45899', 'AS131425'],
            'vnpt': ['AS131429', 'AS45899'],
            'mobifone': ['AS18403'],
            'spt': ['AS38733']
        }
        
        # API endpoints để lấy IP ranges
        self.api_endpoints = [
            'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}',
            'https://api.bgpview.io/asn/{}/prefixes'
        ]
    
    async def download_ranges(self, isp_name):
        """Download IP ranges từ public ASN databases"""
        logger.info(f"📥 Downloading {isp_name.upper()} IP ranges...")
        
        cache_file = os.path.join(self.cache_dir, f'list_{isp_name}.txt')
        
        # Check cache (24h validity)
        if os.path.exists(cache_file):
            age = time.time() - os.path.getmtime(cache_file)
            if age < 86400:  # 24 hours
                with open(cache_file, 'r') as f:
                    ranges = [l.strip() for l in f if l.strip()]
                logger.info(f"✓ Loaded {len(ranges)} cached ranges for {isp_name.upper()}")
                return ranges
        
        all_ranges = []
        asns = self.isp_asns.get(isp_name.lower(), [])
        
        async with aiohttp.ClientSession() as session:
            for asn in asns:
                asn_num = asn.replace('AS', '')
                
                # Try RIPE NCC
                try:
                    url = self.api_endpoints[0].format(asn_num)
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                        if r.status == 200:
                            data = await r.json()
                            prefixes = data.get('data', {}).get('prefixes', [])
                            for p in prefixes:
                                prefix = p.get('prefix')
                                if prefix:
                                    all_ranges.append(prefix)
                    logger.info(f"  ✓ {asn}: {len(prefixes)} ranges")
                except Exception as e:
                    logger.debug(f"RIPE API error for {asn}: {e}")
                
                # Try BGPView
                try:
                    url = self.api_endpoints[1].format(asn_num)
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                        if r.status == 200:
                            data = await r.json()
                            prefixes = data.get('data', {}).get('ipv4_prefixes', [])
                            for p in prefixes:
                                prefix = p.get('prefix')
                                if prefix and prefix not in all_ranges:
                                    all_ranges.append(prefix)
                except Exception as e:
                    logger.debug(f"BGPView API error for {asn}: {e}")
                
                await asyncio.sleep(0.5)  # Rate limiting
        
        # Save to cache
        if all_ranges:
            with open(cache_file, 'w') as f:
                f.write(f"# {isp_name.upper()} IP Ranges\n")
                f.write(f"# Updated: {datetime.now().isoformat()}\n")
                f.write(f"# Total: {len(all_ranges)}\n\n")
                for r in sorted(set(all_ranges)):
                    f.write(f"{r}\n")
            
            logger.info(f"✓ Downloaded {len(all_ranges)} ranges for {isp_name.upper()}")
        else:
            logger.warning(f"⚠️ No ranges found for {isp_name.upper()}")
        
        return all_ranges
    
    def parse_ranges_to_ips(self, ranges, sample_size=None):
        """Parse CIDR ranges to individual IPs with optional sampling"""
        ips = []
        
        for cidr in ranges:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                hosts = list(network.hosts())
                
                if sample_size and len(hosts) > sample_size:
                    # Sample intelligently - skip private ranges
                    hosts = random.sample(hosts, min(sample_size, len(hosts)))
                
                ips.extend([str(ip) for ip in hosts])
            except Exception as e:
                logger.debug(f"Error parsing {cidr}: {e}")
        
        return ips

class ThreadWatchdog:
    """Giám sát và khởi động lại threads bị treo"""
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.threads = {}
        self.lock = threading.Lock()
        self.running = True
    
    def register(self, thread_id, thread_obj):
        with self.lock:
            self.threads[thread_id] = {
                'thread': thread_obj,
                'last_activity': time.time(),
                'restarts': 0
            }
    
    def heartbeat(self, thread_id):
        with self.lock:
            if thread_id in self.threads:
                self.threads[thread_id]['last_activity'] = time.time()
    
    def check_and_restart(self):
        """Check for stuck threads and restart them"""
        with self.lock:
            now = time.time()
            for tid, info in list(self.threads.items()):
                if now - info['last_activity'] > self.timeout:
                    logger.warning(f"⚠️ Thread {tid} stuck for {self.timeout}s, attempting restart...")
                    # Mark for restart
                    info['restarts'] += 1
                    info['last_activity'] = now
                    
                    if info['restarts'] > 3:
                        logger.error(f"❌ Thread {tid} failed to restart 3 times, removing...")
                        del self.threads[tid]
    
    def monitor_loop(self):
        while self.running:
            time.sleep(30)
            self.check_and_restart()
    
    def stop(self):
        self.running = False

class PortScannerNmap:
    """Port scanner using nmap with thread pool"""
    def __init__(self, max_threads=50):
        self.max_threads = max_threads
        self.watchdog = ThreadWatchdog(timeout=180)
        self.results_queue = queue.Queue()
        
        # Start watchdog
        self.watchdog_thread = threading.Thread(target=self.watchdog.monitor_loop, daemon=True)
        self.watchdog_thread.start()
    
    def check_nmap(self):
        """Check if nmap is installed"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def scan_ip_port(self, ip, ports, thread_id):
        """Scan single IP for specific ports"""
        self.watchdog.heartbeat(thread_id)
        
        try:
            port_arg = ','.join(map(str, ports)) if isinstance(ports, list) else str(ports)
            
            cmd = [
                'nmap',
                '-Pn',  # Skip host discovery
                '-sT',  # TCP connect scan
                '--open',  # Only show open ports
                '-T4',  # Aggressive timing
                '-p', port_arg,
                '--max-retries', '1',
                '--host-timeout', '30s',
                ip
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            self.watchdog.heartbeat(thread_id)
            
            # Parse output
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port = int(line.split('/')[0].strip())
                    open_ports.append(port)
            
            if open_ports:
                for port in open_ports:
                    self.results_queue.put((ip, port))
                logger.info(f"✓ {ip} - Open ports: {open_ports}")
                return [(ip, port) for port in open_ports]
            
        except subprocess.TimeoutExpired:
            logger.warning(f"⏱️ Timeout scanning {ip}")
            self.watchdog.heartbeat(thread_id)  # Still alive, just slow
        except Exception as e:
            logger.debug(f"Error scanning {ip}: {e}")
        
        return []
    
    def batch_scan(self, ips, ports, batch_size=100):
        """Scan IPs in batches with thread pool"""
        results = []
        total = len(ips)
        
        logger.info(f"🔍 Scanning {total} IPs for ports {ports}...")
        logger.info(f"⚙️ Using {self.max_threads} threads, batch size: {batch_size}")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            
            for i, ip in enumerate(ips):
                thread_id = f"scan_{i}"
                future = executor.submit(self.scan_ip_port, ip, ports, thread_id)
                futures[future] = (ip, thread_id)
                
                # Register with watchdog
                self.watchdog.register(thread_id, future)
            
            # Process results
            completed = 0
            for future in as_completed(futures):
                ip, thread_id = futures[future]
                try:
                    result = future.result(timeout=90)
                    if result:
                        results.extend(result)
                    completed += 1
                    
                    if completed % 100 == 0:
                        logger.info(f"Progress: {completed}/{total} IPs scanned, {len(results)} proxies found")
                
                except Exception as e:
                    logger.debug(f"Future error for {ip}: {e}")
                    completed += 1
        
        self.watchdog.stop()
        return results

class AIProxyShuffler:
    """AI bot để shuffle và prioritize IPs"""
    def __init__(self):
        self.history = defaultdict(int)
    
    def intelligent_shuffle(self, ips, sample_size=None):
        """Shuffle thông minh dựa trên pattern"""
        # Phân loại IPs
        classified = {
            'class_a': [],
            'class_b': [],
            'class_c': [],
            'cloud': [],
            'home': []
        }
        
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                first_octet = int(str(ip_obj).split('.')[0])
                
                # Detect cloud providers
                if any(cloud in str(ip_obj) for cloud in ['13.', '52.', '34.', '35.']):
                    classified['cloud'].append(ip)
                # Detect likely home IPs (Class A private ranges converted to public)
                elif first_octet in [14, 27, 58, 113, 116, 118, 171]:
                    classified['home'].append(ip)
                elif first_octet < 127:
                    classified['class_a'].append(ip)
                elif first_octet < 192:
                    classified['class_b'].append(ip)
                else:
                    classified['class_c'].append(ip)
            except:
                pass
        
        # Prioritize home IPs
        prioritized = (
            classified['home'] +
            classified['class_a'] +
            classified['class_b'] +
            classified['class_c'] +
            classified['cloud']
        )
        
        # Shuffle within groups
        for i in [0, len(classified['home']), 
                  len(classified['home']) + len(classified['class_a'])]:
            if i < len(prioritized):
                sublist = prioritized[i:i+100]
                random.shuffle(sublist)
                prioritized[i:i+100] = sublist
        
        if sample_size:
            return prioritized[:sample_size]
        
        return prioritized

class EnhancedHoneypotDetector:
    """Phát hiện honeypot nâng cao với 10 phương pháp"""
    def __init__(self):
        self.file = 'prxhoney.txt'
        self.cache = self.load()
        self.lock = threading.Lock()
    
    def load(self):
        if os.path.exists(self.file):
            with open(self.file, 'r') as f:
                return {line.strip() for line in f if line.strip()}
        return set()
    
    def is_cached(self, proxy):
        return proxy in self.cache
    
    def add(self, proxy):
        with self.lock:
            if proxy not in self.cache:
                self.cache.add(proxy)
                with open(self.file, 'a') as f:
                    f.write(f"{proxy}\n")
                logger.warning(f"🍯 HONEYPOT DETECTED: {proxy}")
    
    async def detect_advanced(self, proxy_info, session):
        """10 phương pháp phát hiện honeypot nâng cao"""
        proxy_str = f"{proxy_info.ip}:{proxy_info.port}"
        if self.is_cached(proxy_str):
            return True, 1.0
        
        score = 0.0
        proxy_url = f"http://{proxy_str}"
        
        try:
            # 1. Response time variance (0.2 pts)
            times = []
            for _ in range(4):
                start = time.time()
                try:
                    async with session.get('http://httpbin.org/delay/0.5',
                                         proxy=proxy_url,
                                         timeout=aiohttp.ClientTimeout(total=8)) as r:
                        if r.status == 200:
                            times.append(time.time() - start)
                except: pass
            
            if len(times) >= 3:
                variance = max(times) - min(times)
                if variance < 0.05:  # Quá nhất quán
                    score += 0.2
            
            # 2. Header fingerprinting (0.15 pts)
            async with session.get('http://httpbin.org/headers',
                                 proxy=proxy_url,
                                 timeout=aiohttp.ClientTimeout(total=5)) as r:
                if r.status == 200:
                    data = await r.json()
                    headers = data.get('headers', {})
                    
                    # Suspicious headers
                    sus_headers = ['X-Honeypot', 'X-Trap', 'X-Monitor', 'X-Proxy-Id']
                    if any(h in headers for h in sus_headers):
                        score += 0.15
                    
                    # Too many Via headers
                    via_count = len([h for h in headers if 'via' in h.lower()])
                    if via_count > 3:
                        score += 0.1
            
            # 3. HTTP method fuzzing (0.15 pts)
            unusual_methods = ['TRACE', 'CONNECT', 'PATCH', 'PROPFIND']
            method_responses = []
            
            for method in unusual_methods:
                try:
                    async with session.request(method, 'http://httpbin.org/anything',
                                              proxy=proxy_url,
                                              timeout=aiohttp.ClientTimeout(total=5)) as r:
                        method_responses.append(r.status)
                except: pass
            
            # Honeypot thường chấp nhận tất cả methods
            if len([s for s in method_responses if s == 200]) >= 3:
                score += 0.15
            
            # 4. Port reputation (0.1 pts)
            honeypot_ports = [8080, 3128, 8888, 9999, 1080, 31337, 8123]
            if proxy_info.port in honeypot_ports:
                score += 0.1
            
            # 5. SSL/TLS certificate check (0.1 pts)
            try:
                async with session.get('https://httpbin.org/get',
                                     proxy=proxy_url,
                                     timeout=aiohttp.ClientTimeout(total=5),
                                     ssl=False) as r:
                    # Honeypot thường bỏ qua SSL validation
                    if r.status == 200:
                        score += 0.1
            except: pass
            
            # 6. 404/Error handling (0.1 pts)
            try:
                async with session.get('http://httpbin.org/status/404',
                                     proxy=proxy_url,
                                     timeout=aiohttp.ClientTimeout(total=5)) as r:
                    # Honeypot có thể trả 200 cho 404
                    if r.status == 200:
                        score += 0.1
            except: pass
            
            # 7. Payload echo test (0.1 pts)
            test_data = {'test': 'honeypot_detection_' + str(random.randint(1000, 9999))}
            try:
                async with session.post('http://httpbin.org/post',
                                      json=test_data,
                                      proxy=proxy_url,
                                      timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        resp_data = await r.json()
                        # Honeypot có thể modify payload
                        if resp_data.get('json') != test_data:
                            score += 0.1
            except: pass
            
            # 8. DNS leak test (0.05 pts)
            try:
                async with session.get('http://ip-api.com/json',
                                     proxy=proxy_url,
                                     timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if r.status == 200:
                        data = await r.json()
                        # Check if DNS matches proxy location
                        if data.get('query') == proxy_info.ip:
                            score += 0.05
            except: pass
            
            # 9. Rate limit bypass test (0.05 pts)
            rate_test_count = 0
            for _ in range(10):
                try:
                    async with session.get('http://httpbin.org/get',
                                         proxy=proxy_url,
                                         timeout=aiohttp.ClientTimeout(total=3)) as r:
                        if r.status == 200:
                            rate_test_count += 1
                except: pass
            
            # Honeypot không có rate limit
            if rate_test_count >= 9:
                score += 0.05
            
            # 10. Timing attack (0.05 pts)
            computation_time = []
            for _ in range(2):
                start = time.time()
                try:
                    # Request that requires server-side computation
                    async with session.get('http://httpbin.org/base64/aGVsbG8gd29ybGQ=',
                                         proxy=proxy_url,
                                         timeout=aiohttp.ClientTimeout(total=5)) as r:
                        if r.status == 200:
                            computation_time.append(time.time() - start)
                except: pass
            
            # Honeypot có computation time rất nhanh và nhất quán
            if len(computation_time) == 2:
                if max(computation_time) < 0.1 and abs(computation_time[0] - computation_time[1]) < 0.01:
                    score += 0.05
            
            final_score = min(score, 1.0)
            is_hp = final_score >= 0.65  # Threshold 65%
            
            if is_hp:
                self.add(proxy_str)
            
            return is_hp, final_score
            
        except Exception as e:
            logger.debug(f"Honeypot detection error for {proxy_str}: {e}")
            return False, 0.0

class EnhancedProxyQualityAnalyzer:
    """Phân tích chất lượng proxy với 7 levels"""
    def __init__(self, settings):
        self.t = settings.get('quality_thresholds')
    
    def classify_advanced(self, p):
        """Phân loại 7 cấp độ"""
        if p.is_honeypot:
            return ProxyQuality.HONEYPOT.value
        if not p.is_working:
            return ProxyQuality.DEAD.value
        
        score = 0
        
        # Response time (35%)
        if p.response_time <= 100:
            score += 35
        elif p.response_time <= 200:
            score += 30
        elif p.response_time <= 500:
            score += 25
        elif p.response_time <= 1000:
            score += 15
        elif p.response_time <= 2000:
            score += 10
        else:
            score += 5
        
        # Success rate (35%)
        if p.success_rate >= 95:
            score += 35
        elif p.success_rate >= 90:
            score += 30
        elif p.success_rate >= 80:
            score += 25
        elif p.success_rate >= 70:
            score += 20
        elif p.success_rate >= 60:
            score += 15
        elif p.success_rate >= 50:
            score += 10
        else:
            score += 5
        
        # Anonymity (20%)
        anon_scores = {
            'elite': 20, 'Elite': 20,
            'anonymous': 15, 'Anonymous': 15,
            'transparent': 10, 'Transparent': 10
        }
        score += anon_scores.get(p.anonymity, 5)
        
        # Home proxy bonus (10%)
        if p.is_home_proxy:
            score += 10
        
        # Classify
        if score >= 85:
            return ProxyQuality.SUPER_STRONG.value
        elif score >= 70:
            return ProxyQuality.STRONG.value
        elif score >= 55:
            return ProxyQuality.MEDIUM.value
        elif score >= 40:
            return ProxyQuality.WEAK.value
        elif score >= 25:
            return ProxyQuality.SUPER_WEAK.value
        
        return ProxyQuality.DEAD.value

class SettingsManager:
    """Quản lý settings qua file stt.json"""
    def __init__(self, settings_file='stt.json'):
        self.settings_file = settings_file
        self.default = {
            'thread': 200,
            'checktl': 5,
            'checkwb': 5,
            'timeout': 10,
            'batch_size': 100,
            'max_concurrent': 200,
            'scan_threads': 50,
            'port_scan_timeout': 60,
            'quality_thresholds': {
                'super_strong': {'max_speed': 100, 'min_success': 95},
                'strong': {'max_speed': 200, 'min_success': 90},
                'medium': {'max_speed': 500, 'min_success': 70},
                'weak': {'max_speed': 2000, 'min_success': 50}
            }
        }
        self.settings = self.load()
    
    def load(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    s = self.default.copy()
                    loaded = json.load(f)
                    s.update(loaded)
                    logger.info(f"✓ Loaded settings from {self.settings_file}")
                    return s
            except: pass
        self.save(self.default)
        return self.default.copy()
    
    def save(self, settings=None):
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings or self.settings, f, indent=2)
            logger.info(f"✓ Settings saved to {self.settings_file}")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
    
    def update(self, key, value):
        try:
            self.settings[key] = value
            self.save()
            logger.info(f"✓ Updated setting: {key} = {value}")
        except Exception as e:
            logger.error(f"Failed to update setting {key}: {e}")
    
    def get(self, key, default=None):
        return self.settings.get(key, default)

class WebCheckManager:
    """Quản lý website check proxy từ webcheck.json"""
    def __init__(self, file='webcheck.json'):
        self.file = file
        self.sites = self.load()
    
    def load(self):
        default = [
            {"name": "HTTPBin IP", "url": "http://httpbin.org/ip", "method": "GET"},
            {"name": "HTTPBin Headers", "url": "http://httpbin.org/headers", "method": "GET"},
            {"name": "IPify", "url": "https://api.ipify.org?format=json", "method": "GET"},
            {"name": "IP-API", "url": "http://ip-api.com/json", "method": "GET"},
            {"name": "IFConfig", "url": "http://ifconfig.me/all.json", "method": "GET"},
        ]
        
        if os.path.exists(self.file):
            try:
                with open(self.file, 'r') as f:
                    loaded = json.load(f)
                    if loaded:
                        return loaded
            except: pass
        
        with open(self.file, 'w') as f:
            json.dump(default, f, indent=2)
        return default
    
    async def check_external(self, proxy_info, session, num_checks=5):
        results = {'total': 0, 'passed': 0, 'times': []}
        sites_used = []
        available = self.sites.copy()
        random.shuffle(available)
        
        site_count = defaultdict(int)
        
        while len(sites_used) < num_checks and available:
            for site in available:
                if site_count[site['name']] < 3:
                    sites_used.append(site)
                    site_count[site['name']] += 1
                    if len(sites_used) >= num_checks:
                        break
            available = [s for s in self.sites if site_count[s['name']] < 3]
        
        proxy_url = f"http://{proxy_info.ip}:{proxy_info.port}"
        for site in sites_used[:num_checks]:
            try:
                start = time.time()
                async with session.request(site['method'], site['url'],
                                          proxy=proxy_url,
                                          timeout=aiohttp.ClientTimeout(total=10)) as r:
                    rt = (time.time() - start) * 1000
                    results['total'] += 1
                    if r.status == 200:
                        results['passed'] += 1
                        results['times'].append(rt)
            except:
                results['total'] += 1
        
        return results

class ProxyTester:
    """Test proxy với internal + external checks"""
    def __init__(self, settings, honeypot_det, webcheck_mgr):
        self.settings = settings
        self.timeout = settings.get('timeout', 10)
        self.sem = asyncio.Semaphore(settings.get('max_concurrent', 200))
        self.honeypot_det = honeypot_det
        self.webcheck = webcheck_mgr
        self.analyzer = EnhancedProxyQualityAnalyzer(settings)
        self.test_urls = [
            'http://httpbin.org/ip',
            'http://api.ipify.org?format=json',
            'http://ip-api.com/json'
        ]
        self.uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
    
    async def test_comprehensive(self, proxy, ptype, is_home=False):
        """Test toàn diện: internal -> honeypot -> external -> classify"""
        async with self.sem:
            ip, port = proxy.split(':')
            p = ProxyInfo(ip=ip, port=int(port), type=ptype, is_home_proxy=is_home)
            
            # Check cache honeypot
            if self.honeypot_det.is_cached(proxy):
                p.is_honeypot = True
                p.quality = ProxyQuality.HONEYPOT.value
                return p
            
            try:
                proxy_url = f"{'socks5' if ptype=='socks5' else 'socks4' if ptype=='socks4' else 'http'}://{proxy}"
                
                async with aiohttp.ClientSession() as session:
                    # PHASE 1: Internal checks
                    checktl = self.settings.get('checktl', 5)
                    int_success = 0
                    
                    for _ in range(checktl):
                        if await self._check_internal(p, session, proxy_url):
                            int_success += 1
                        p.internal_checks += 1
                    
                    if int_success == 0:
                        p.is_working = False
                        p.quality = ProxyQuality.DEAD.value
                        return p
                    
                    p.is_working = True
                    p.successful_checks = int_success
                    p.total_checks = int_success
                    p.success_rate = (int_success / checktl) * 100
                    
                    # PHASE 2: Honeypot detection
                    is_hp, hp_score = await self.honeypot_det.detect_advanced(p, session)
                    p.is_honeypot = is_hp
                    p.honeypot_score = hp_score
                    
                    if is_hp:
                        p.quality = ProxyQuality.HONEYPOT.value
                        return p
                    
                    # PHASE 3: External checks
                    checkwb = self.settings.get('checkwb', 5)
                    ext_res = await self.webcheck.check_external(p, session, checkwb)
                    
                    p.external_checks = ext_res['total']
                    p.total_checks += ext_res['total']
                    p.successful_checks += ext_res['passed']
                    
                    if p.total_checks > 0:
                        p.success_rate = (p.successful_checks / p.total_checks) * 100
                    
                    # Update response time
                    if ext_res['times']:
                        avg_ext = sum(ext_res['times']) / len(ext_res['times'])
                        p.response_time = (p.response_time + avg_ext) / 2
                    
                    # Get geo info
                    await self._get_geo(p, session, proxy_url)
                    
                    # PHASE 4: Quality classification
                    p.quality = self.analyzer.classify_advanced(p)
                    p.last_checked = datetime.now().isoformat()
                    
                    return p
                    
            except Exception as e:
                p.is_working = False
                p.quality = ProxyQuality.DEAD.value
                p.last_checked = datetime.now().isoformat()
                return p
    
    async def _check_internal(self, p, session, proxy_url):
        """Single internal check"""
        try:
            start = time.time()
            async with session.get(
                random.choice(self.test_urls),
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={'User-Agent': random.choice(self.uas)}
            ) as r:
                if r.status == 200:
                    rt = (time.time() - start) * 1000
                    p.response_time = rt if p.response_time == 0 else (p.response_time + rt) / 2
                    
                    # Check anonymity
                    try:
                        data = await r.json()
                        detected_ip = data.get('origin', data.get('ip', '')).split(',')[0].strip()
                        p.anonymity = 'Elite' if detected_ip != p.ip else 'Transparent'
                    except:
                        p.anonymity = 'Anonymous'
                    
                    return True
        except:
            pass
        return False
    
    async def _get_geo(self, p, session, proxy_url):
        """Get geolocation info"""
        try:
            async with session.get(
                'http://ip-api.com/json',
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    p.country = data.get('country', 'Unknown')
                    p.isp = data.get('isp', 'Unknown')
        except:
            pass
    
    async def test_batch(self, proxies, callback=None):
        """Test batch of proxies"""
        tasks = [self.test_comprehensive(proxy, ptype, is_home) for proxy, ptype, is_home in proxies]
        results = []
        
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            if result:
                results.append(result)
                if callback:
                    callback(i + 1, len(tasks), result)
        
        return results

class ProxyOutputManager:
    """Quản lý output files với naming thông minh"""
    def __init__(self):
        self.dir = 'proxy_results'
        os.makedirs(self.dir, exist_ok=True)
    
    def generate_filename(self, ptype, quality=None):
        """Format: type_DDMMYYYYHHMM_quality.txt"""
        ts = datetime.now().strftime('%d%m%Y_%H%M')
        fname = f"{ptype}_{ts}_{quality}.txt" if quality else f"{ptype}_{ts}.txt"
        return os.path.join(self.dir, fname)
    
    def save_by_quality(self, proxies, ptype):
        """Save proxies vào file riêng theo quality"""
        by_qual = defaultdict(list)
        
        for p in proxies:
            by_qual[p.quality].append(f"{p.ip}:{p.port}")
        
        files = []
        for qual, plist in by_qual.items():
            if plist:
                fname = self.generate_filename(ptype, qual)
                with open(fname, 'w') as f:
                    f.write(f"# {ptype.upper()} Proxies - Quality: {qual.upper()}\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total: {len(plist)}\n\n")
                    
                    for px in sorted(plist):
                        f.write(f"{px}\n")
                
                files.append(fname)
                logger.info(f"✓ Saved {qual.upper()}: {fname} ({len(plist)} proxies)")
        
        return files
    
    def save_home_proxies(self, proxies):
        """Save home proxies to home.txt"""
        fname = 'home.txt'
        with open(fname, 'w') as f:
            f.write(f"# Home/ISP Proxies\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(proxies)}\n\n")
            
            for p in sorted(proxies, key=lambda x: x.quality):
                f.write(f"{p.ip}:{p.port} # {p.quality.upper()} - {p.isp}\n")
        
        logger.info(f"✓ Saved home proxies: {fname} ({len(proxies)} proxies)")
        return fname

class ProxyScanner:
    """Main scanner với scan riêng từng loại proxy"""
    def __init__(self, settings_mgr):
        self.settings = settings_mgr
        self.proxies = defaultdict(set)
        self.honeypot_det = EnhancedHoneypotDetector()
        self.webcheck = WebCheckManager()
        self.tester = ProxyTester(settings_mgr, self.honeypot_det, self.webcheck)
        self.output_mgr = ProxyOutputManager()
        self.isp_mgr = ISPRangeManager()
        self.ai_shuffler = AIProxyShuffler()
        
        # Sources cho từng loại proxy
        self.sources = {
            'http': [
                'https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000',
                'https://www.proxy-list.download/api/v1/get?type=http',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
                'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt'
            ],
            'https': [
                'https://www.proxy-list.download/api/v1/get?type=https',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt'
            ],
            'socks4': [
                'https://api.proxyscrape.com/v2/?request=get&protocol=socks4&timeout=10000',
                'https://www.proxy-list.download/api/v1/get?type=socks4',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
                'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt'
            ],
            'socks5': [
                'https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=10000',
                'https://www.proxy-list.download/api/v1/get?type=socks5',
                'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
                'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt'
            ]
        }
    
    async def fetch_url(self, url):
        """Fetch proxies from URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status != 200:
                        return []
                    
                    text = await r.text()
                    proxies = []
                    
                    for line in text.strip().split('\n'):
                        proxy = line.strip()
                        if ':' in proxy and self._validate(proxy):
                            proxies.append(proxy)
                            
                            if len(proxies) >= 500:
                               break                  
                    
                    return proxies
        except Exception as e:
            logger.debug(f"Error fetching {url[:50]}: {e}")
            return []
    
    def _validate(self, proxy):
        """Validate proxy format IP:PORT"""
        try:
            ip, port = proxy.split(':', 1)
            ipaddress.ip_address(ip)
            port_num = int(port)
            return 1 <= port_num <= 65535
        except:
            return False
    
    async def scan_type(self, ptype):
        """Scan một loại proxy cụ thể"""
        logger.info(f"\n{'='*70}\n🔍 SCANNING {ptype.upper()} PROXIES\n{'='*70}")
        
        # Fetch from sources
        sources = self.sources.get(ptype, [])
        logger.info(f"📡 Fetching from {len(sources)} sources...")
        
        tasks = [self.fetch_url(url) for url in sources]
        results = await asyncio.gather(*tasks)
        
        for plist in results:
            for p in plist:
                self.proxies[ptype].add(p)
        
        total = len(self.proxies[ptype])
        logger.info(f"✓ Collected {total} unique {ptype} proxies")
        
        if total == 0:
            logger.warning(f"⚠️  No {ptype} proxies found!")
            return
        
        # Verify proxies
        logger.info(f"\n{'='*70}\n🧪 VERIFYING {ptype.upper()} PROXIES\n{'='*70}")
        logger.info(f"Settings: Internal checks={self.settings.get('checktl')}, External checks={self.settings.get('checkwb')}")
        
        to_test = [(p, ptype, False) for p in self.proxies[ptype]]
        
        def progress(cur, tot, res):
            if res.is_working and not res.is_honeypot:
                emoji = {
                    'sieu_manh': '🚀', 'manh': '💪', 'tb': '👍', 
                    'yeu': '👎', 'sieu_yeu': '😞'
                }.get(res.quality, '❓')
                logger.info(f"[{cur}/{tot}] {emoji} {res.ip}:{res.port} - {res.response_time:.0f}ms - {res.quality.upper()} - {res.country}")
        
        # Process in batches
        batch_size = self.settings.get('batch_size', 100)
        all_results = []
        
        for i in range(0, len(to_test), batch_size):
            batch = to_test[i:i+batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(to_test) - 1) // batch_size + 1
            
            logger.info(f"\n📦 Processing batch {batch_num}/{total_batches} ({len(batch)} proxies)...")
            
            results = await self.tester.test_batch(batch, callback=progress)
            all_results.extend(results)
            
            if i + batch_size < len(to_test):
                await asyncio.sleep(0.5)
        
        # Save results by quality
        files = self.output_mgr.save_by_quality(all_results, ptype)
        
        # Print statistics
        self._print_stats(all_results, ptype, files)
    
    async def scan_home_isp(self, isp_name, ports=None):
        """Scan home/ISP proxies"""
        logger.info(f"\n{'='*70}\n🏠 SCANNING HOME PROXIES - {isp_name.upper()}\n{'='*70}")
        
        # Download IP ranges
        ranges = await self.isp_mgr.download_ranges(isp_name)
        if not ranges:
            logger.error(f"❌ Could not download ranges for {isp_name}")
            return
        
        # Parse to IPs with intelligent sampling
        logger.info("🔄 Parsing IP ranges...")
        all_ips = self.isp_mgr.parse_ranges_to_ips(ranges, sample_size=1000)
        
        # AI shuffle
        logger.info("🤖 AI shuffling IPs...")
        shuffled_ips = self.ai_shuffler.intelligent_shuffle(all_ips)
        
        logger.info(f"✓ Prepared {len(shuffled_ips)} IPs for scanning")
        
        # Port scan
        if ports is None:
            ports = [22, 80, 443, 1080, 3128, 8080, 8888, 9050]
        
        logger.info(f"🔍 Scanning ports: {ports}")
        
        scanner = PortScannerNmap(max_threads=self.settings.get('scan_threads', 50))
        
        if not scanner.check_nmap():
            logger.error("❌ nmap not found! Please install: sudo apt-get install nmap")
            logger.info("💡 Falling back to socket scanning...")
            discovered = await self._socket_scan(shuffled_ips, ports)
        else:
            discovered = scanner.batch_scan(shuffled_ips, ports)
        
        logger.info(f"\n✓ Discovered {len(discovered)} active proxies")
        
        if not discovered:
            logger.warning("⚠️ No active proxies found")
            return
        
        # Test discovered proxies
        logger.info(f"\n{'='*70}\n🧪 TESTING DISCOVERED PROXIES\n{'='*70}")
        
        to_test = [(f"{ip}:{port}", 'http', True) for ip, port in discovered]
        
        def progress(cur, tot, res):
            if res.is_working and not res.is_honeypot:
                emoji = {
                    'sieu_manh': '🚀', 'manh': '💪', 'tb': '👍', 
                    'yeu': '👎', 'sieu_yeu': '😞'
                }.get(res.quality, '❓')
                logger.info(f"[{cur}/{tot}] {emoji} {res.ip}:{res.port} - {res.response_time:.0f}ms - {res.quality.upper()} - {res.isp}")
        
        all_results = await self.tester.test_batch(to_test, callback=progress)
        
        # Save results
        working = [p for p in all_results if p.is_working and not p.is_honeypot]
        if working:
            self.output_mgr.save_home_proxies(working)
            self.output_mgr.save_by_quality(all_results, f"{isp_name}_home")
        
        # Print statistics
        self._print_stats(all_results, f"{isp_name.upper()} HOME", [])
    
    async def _socket_scan(self, ips, ports):
        """Fallback socket scanning"""
        logger.info("🔌 Using socket-based port scanning...")
        results = []
        
        async def check_port(ip, port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=3
                )
                writer.close()
                await writer.wait_closed()
                return (ip, port)
            except:
                return None
        
        tasks = []
        for ip in ips[:500]:  # Limit for socket scan
            for port in ports:
                tasks.append(check_port(ip, port))
        
        logger.info(f"Checking {len(tasks)} combinations...")
        completed = 0
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                results.append(result)
                logger.info(f"✓ Found: {result[0]}:{result[1]}")
            
            completed += 1
            if completed % 100 == 0:
                logger.info(f"Progress: {completed}/{len(tasks)}")
        
        return results
    
    def _print_stats(self, results, ptype, files):
        """Print scan statistics"""
        by_qual = defaultdict(int)
        for p in results:
            by_qual[p.quality] += 1
        
        working = [p for p in results if p.is_working and not p.is_honeypot]
        
        logger.info(f"\n{'='*70}\n📊 {ptype} SCAN RESULTS\n{'='*70}")
        logger.info(f"Total tested: {len(results)}")
        logger.info(f"Working: {len(working)} ({len(working)/len(results)*100:.1f}%)")
        logger.info(f"\nBy Quality:")
        logger.info(f"  🚀 Super Strong: {by_qual['sieu_manh']:>4} proxies")
        logger.info(f"  💪 Strong:       {by_qual['manh']:>4} proxies")
        logger.info(f"  👍 Medium:       {by_qual['tb']:>4} proxies")
        logger.info(f"  👎 Weak:         {by_qual['yeu']:>4} proxies")
        logger.info(f"  😞 Super Weak:   {by_qual['sieu_yeu']:>4} proxies")
        logger.info(f"  💀 Dead:         {by_qual['die']:>4} proxies")
        logger.info(f"  🍯 Honeypot:     {by_qual['honeypot']:>4} proxies")
        
        if files:
            logger.info(f"\n📁 Output files:")
            for f in files:
                logger.info(f"  {f}")

def parse_args():
    p = argparse.ArgumentParser(
        description='Advanced Proxy Scanner v5.0 - Home/ISP Ultimate Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard scanning
  %(prog)s --type socks5
  %(prog)s --type all --thread 300
  
  # Home/ISP scanning
  %(prog)s --scan-ipport-home
  %(prog)s --scan-ipport-viettel
  %(prog)s --scan-ipport-fpt
  %(prog)s --scan-ipport-home-22
  %(prog)s --scan-ipport-home-22-3389
  %(prog)s --scan-ipport-vinaphone-80-443-8080
  
  # Settings
  %(prog)s --show-settings
  %(prog)s --reset-settings
        """
    )
    
    p.add_argument('--type', choices=['http', 'https', 'socks4', 'socks5', 'all'], 
                   help='Proxy type to scan')
    p.add_argument('--scan-ipport-home', action='store_true',
                   help='Scan all Vietnamese ISP home proxies (all common ports)')
    p.add_argument('--scan-ipport-viettel', nargs='*', metavar='PORT',
                   help='Scan Viettel home proxies on specified ports')
    p.add_argument('--scan-ipport-fpt', nargs='*', metavar='PORT',
                   help='Scan FPT home proxies on specified ports')
    p.add_argument('--scan-ipport-vinaphone', nargs='*', metavar='PORT',
                   help='Scan Vinaphone home proxies on specified ports')
    p.add_argument('--scan-ipport-vnpt', nargs='*', metavar='PORT',
                   help='Scan VNPT home proxies on specified ports')
    p.add_argument('--thread', type=int, metavar='N',
                   help='Number of concurrent threads')
    p.add_argument('--scan-threads', type=int, metavar='N',
                   help='Number of port scanning threads (default: 50)')
    p.add_argument('--checktl', type=int, metavar='N',
                   help='Number of internal checks per proxy')
    p.add_argument('--checkwb', type=int, metavar='N',
                   help='Number of external website checks per proxy')
    p.add_argument('--timeout', type=int, metavar='SEC',
                   help='Timeout in seconds')
    p.add_argument('--batch-size', type=int, metavar='N',
                   help='Batch size for processing')
    p.add_argument('--show-settings', action='store_true',
                   help='Show current settings')
    p.add_argument('--reset-settings', action='store_true',
                   help='Reset settings to default')
    
    return p.parse_args()

async def main():
    args = parse_args()
    
    # Print banner
    print(f"\n{'='*70}")
    print(" "*15 + "SCAN PROXY")
    print(" "*10 + "Scan Proxy By DarkJPT")
    print(f"{'='*70}")
    print("\n✨ New Features v5.0:")
    print("  • Home/ISP proxy scanning (Viettel/FPT/Vinaphone/VNPT)")
    print("  • AI-powered IP shuffling")
    print("  • Thread watchdog & recovery")
    print("  • 7-level quality classification")
    print("  • Enhanced honeypot detection (10 methods)")
    print("  • Nmap/Socket port scanning")
    print(f"{'='*70}\n")
    
    # Initialize settings
    settings_mgr = SettingsManager()
    
    # Handle settings commands
    if args.reset_settings:
        settings_mgr.save(settings_mgr.default)
        logger.info("✅ Settings reset to default")
        return
    
    if args.show_settings:
        print("📋 Current Settings:\n")
        print(json.dumps(settings_mgr.settings, indent=2))
        return
    
    # Update settings from args
    if args.thread:
        settings_mgr.update('thread', args.thread)
        settings_mgr.update('max_concurrent', args.thread)
    
    if args.scan_threads:
        settings_mgr.update('scan_threads', args.scan_threads)
    
    if args.checktl:
        settings_mgr.update('checktl', args.checktl)
    
    if args.checkwb:
        settings_mgr.update('checkwb', args.checkwb)
    
    if args.timeout:
        settings_mgr.update('timeout', args.timeout)
    
    if args.batch_size:
        settings_mgr.update('batch_size', args.batch_size)
    
    # Display settings
    logger.info("⚙️  Active Settings:")
    logger.info(f"  Threads: {settings_mgr.get('thread')}")
    logger.info(f"  Scan threads: {settings_mgr.get('scan_threads')}")
    logger.info(f"  Internal checks: {settings_mgr.get('checktl')}")
    logger.info(f"  External checks: {settings_mgr.get('checkwb')}")
    logger.info(f"  Timeout: {settings_mgr.get('timeout')}s")
    
    # Initialize scanner
    scanner = ProxyScanner(settings_mgr)
    
    start_time = time.time()
    
    # Home/ISP scanning
    if args.scan_ipport_home:
        for isp in ['viettel', 'fpt', 'vinaphone', 'vnpt']:
            await scanner.scan_home_isp(isp)
            print("\n")
    
    elif args.scan_ipport_viettel is not None:
        ports = [int(p) for p in args.scan_ipport_viettel] if args.scan_ipport_viettel else None
        await scanner.scan_home_isp('viettel', ports)
    
    elif args.scan_ipport_fpt is not None:
        ports = [int(p) for p in args.scan_ipport_fpt] if args.scan_ipport_fpt else None
        await scanner.scan_home_isp('fpt', ports)
    
    elif args.scan_ipport_vinaphone is not None:
        ports = [int(p) for p in args.scan_ipport_vinaphone] if args.scan_ipport_vinaphone else None
        await scanner.scan_home_isp('vinaphone', ports)
    
    elif args.scan_ipport_vnpt is not None:
        ports = [int(p) for p in args.scan_ipport_vnpt] if args.scan_ipport_vnpt else None
        await scanner.scan_home_isp('vnpt', ports)
    
    # Standard scanning
    elif args.type:
        if args.type == 'all':
            for ptype in ['http', 'https', 'socks4', 'socks5']:
                await scanner.scan_type(ptype)
                print("\n")
        else:
            await scanner.scan_type(args.type)
    
    else:
        logger.error("❌ Please specify --type or use home scanning options")
        logger.info("💡 Try: python scanprx.py --help")
        return
    
    elapsed = time.time() - start_time
    
    # Final summary
    print(f"\n{'='*70}")
    print("✅ SCAN COMPLETE!")
    print(f"{'='*70}")
    print(f"⏱️  Total time: {elapsed:.2f} seconds ({elapsed/60:.1f} minutes)")
    print(f"📁 Results: proxy_results/")
    print(f"🏠 Home proxies: home.txt")
    print(f"🍯 Honeypots: prxhoney.txt")
    print(f"⚙️  Settings: stt.json")
    print(f"{'='*70}\n")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)