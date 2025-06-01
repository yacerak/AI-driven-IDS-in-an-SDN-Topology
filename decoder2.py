# nslkdd_decoder.py
from scapy.all import *
from collections import defaultdict
import time
import re
import logging
from typing import Callable, Optional

DEFAULT_CONFIG = {
    'service_map': {
        # TCP/UDP Services
        80: 'http',
        443: 'http_443',
        8001: 'http_8001',
        2784: 'http_2784',
        25: 'smtp',
        79: 'finger',
        53: 'domain_u',
        113: 'auth',
        23: 'telnet',
        21: 'ftp',
        20: 'ftp_data',
        2050: 'eco_i',
        123: 'ntp_u',
        2674: 'ecr_i',
        77: 'rje',
        37: 'time',
        1911: 'mtp',
        245: 'link',
        71: 'remote_job',
        70: 'gopher',
        22: 'ssh',
        42: 'name',
        43: 'whois',
        513: 'login',
        143: 'imap4',
        13: 'daytime',
        84: 'ctf',
        119: 'nntp',
        514: 'shell',
        194: 'IRC',
        433: 'nnsp',
        512: 'exec',
        515: 'printer',
        520: 'efs',
        530: 'courier',
        540: 'uucp',
        543: 'klogin',
        544: 'kshell',
        7: 'echo',
        9: 'discard',
        11: 'systat',
        95: 'supdup',
        102: 'iso_tsap',
        101: 'hostnames',
        105: 'csnet_ns',
        109: 'pop_2',
        111: 'sunrpc',
        117: 'uucp_path',
        137: 'netbios_ns',
        139: 'netbios_ssn',
        138: 'netbios_dgm',
        150: 'sql_net',
        175: 'vmnet',
        179: 'bgp',
        210: 'Z39_50',
        389: 'ldap',
        15: 'netstat',
        5000: 'urh_i',
        6000: 'X11',
        5001: 'urp_i',
        5002: 'pm_dump',
        69: 'tftp_u',
        525: 'tim_i',
        5003: 'red_i',
        5190: 'aol',
        2813: 'harvest',
        # ICMP and others
        None: 'icmp',
        0: 'other',
        1: 'private'
    },
    
    'flag_map': {
        'F': 'OTH',      # FIN → OTH
        'S': 'S0',       # SYN → S0
        'SA': 'S1',      # SYN-ACK → S1
        'R': 'REJ',      # RST → REJ
        'RA': 'RSTR',    # RST-ACK → RSTR
        '': 'OTH',       # No flags → OTH
        'SF': 'SF',      # SYN-FIN → SF
    },
    
    'window_size': 100,
    'enable_dpi': True,
    'timeout': None
}

class NSLKDDDecoder:
    """A modular NSL-KDD network traffic feature extractor"""
    
    def __init__(self, 
                 feature_callback: Optional[Callable] = None,
                 config: Optional[dict] = None):

        self.feature_callback = feature_callback
        self.config = self._load_default_config(config)
        self.connection_stats = defaultdict(self._init_connection_stats)
        self.logger = logging.getLogger('NSLKDDDecoder')
        self.running = False

        # Configure Scapy to use pcap for accurate capture (if needed)
        conf.use_pcap = True

    def _load_default_config(self, user_config: Optional[dict]) -> dict:
        """Load default configuration with optional user overrides"""
        default_config = DEFAULT_CONFIG.copy()
        if user_config:
            default_config.update(user_config)
        return default_config

    def _init_connection_stats(self) -> dict:
        """Initialize a connection stats template"""
        return {
            'wrong_fragment': 0,
            'urgent': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'num_failed_logins': 0,
            'duration': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
            'start_time': time.time(),
            'last_100_connections': []  # For traffic window calculations
        }

    def start(self, interface: str = None, offline: str = None):
        """
        Start the packet processing
        
        :param interface: Network interface to monitor
        :param offline: PCAP file path for offline analysis
        """
        if offline:
            self._process_offline(offline)
        else:
            self._start_live_capture(interface)

    def stop(self):
        """Stop packet processing"""
        self.running = False

    def _start_live_capture(self, interface: str):
        """Start live packet capture"""
        self.running = True
        sniff(
            prn=self.packet_handler,
            filter="ip",
            store=False,
            iface=interface,
            stop_filter=lambda _: not self.running
        )

    def _process_offline(self, pcap_file: str):
        """Process packets from a PCAP file"""
        packets = rdpcap(pcap_file)
        for pkt in packets:
            self.packet_handler(pkt)

    def packet_handler(self, pkt):
        """
        Scapy callback: extract features, update stats, and invoke the feature callback
        """
        try:
            # Only process IP packets
            if not pkt.haslayer(IP):
                return

            # Build connection key and ensure initialization
            key = self._get_connection_key(pkt)
            self._init_connection(pkt, key)

            # Update all feature categories
            self._update_basic_features(pkt, key)
            if self.config.get('enable_dpi', False):
                self._update_content_features(pkt, key)
            self._update_traffic_features(key)
            self._update_host_stats(key)

            # On connection close, finalize and callback
            if self._is_connection_closed(pkt):
                features = self._finalize_features(key)
                # include metadata for callback
                features['src_ip'] = key[0]
                features['dst_ip'] = key[1]
                self._handle_features(features)

        except Exception as e:
            self.logger.error(f"packet_handler error: {e}")

    def _get_connection_key(self, pkt) -> tuple:
        """Create connection identifier tuple"""
        return (
            pkt[IP].src, pkt[IP].dst,
            pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0,
            pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0
        )

    def _init_connection(self, pkt, key):
        """Initialize connection tracking for a new connection if not already set"""
        if key not in self.connection_stats:
            self.connection_stats[key] = self._init_connection_stats()
            # Also store static info about the connection
            self.connection_stats[key]['dst_ip'] = pkt[IP].dst
            self.connection_stats[key]['service'] = self._get_service(pkt)
            self.connection_stats[key]['start_time'] = time.time()

    def _update_basic_features(self, pkt, key):
        """Update basic packet features"""
        if pkt.haslayer(Raw):
            payload_size = len(pkt[Raw])
            if pkt[IP].src == key[0]:
                self.connection_stats[key]['src_bytes'] += payload_size
            else:
                self.connection_stats[key]['dst_bytes'] += payload_size

    def _update_content_features(self, pkt, key):
        """Deep packet inspection features"""
        payload = bytes(pkt.payload) if pkt.payload else b''
        stats = self.connection_stats[key]
        # Extract ID from payload
        id_start = payload.find(b'ID=')
        if id_start != -1:
            id_str = payload[id_start:].split(b'\x00')[0].decode()
            stats['row_id'] = int(id_str.split('=')[1])
        
        # Login detection
        if b'login' in payload.lower():
            stats['num_failed_logins'] += payload.count(b'fail')
            stats['logged_in'] = 1 if b'success' in payload else 0
        
        # Shell detection
        if any(cmd in payload for cmd in [b'sh', b'bash', b'zsh', b'powershell']):
            stats['num_shells'] += 1

        # File operations
        stats['num_file_creations'] += len(re.findall(
            rb'(rm|mv|cp|touch|echo)\s+\S+', payload
        ))

        # Privilege escalation
        if b'su ' in payload or b'sudo ' in payload:
            stats['su_attempted'] += 1

    def _update_traffic_features(self, key):
        """Update traffic pattern statistics"""
        stats = self.connection_stats[key]
        # Increase weight for port scanning behavior
        if stats['service'] == 'suspicious_scan':
            stats['count'] *= 2 
        # For demonstration, assume last_100_connections is a list of past connection stats
        window = stats['last_100_connections'][-self.config['window_size']:]
        
        stats['count'] = len(window)
        stats['srv_count'] = sum(1 for c in window if c.get('service') == stats.get('service'))
        
        same_srv = sum(1 for c in window if c.get('service') == stats.get('service'))
        stats['same_srv_rate'] = self._safe_divide(same_srv, stats['count'])
        stats['diff_srv_rate'] = 1 - stats['same_srv_rate']

    def _update_host_stats(self, key):
        """Calculate destination host statistics"""
        stats = self.connection_stats[key]
        if stats['service'] == 'icmp' and stats['count'] > 1000:
            stats['serror_rate'] = 1.0 
        host_conns = [c for c in self.connection_stats.values() if c.get('dst_ip') == stats.get('dst_ip')]
    
        stats['dst_host_count'] = len(host_conns)
        stats['dst_host_srv_count'] = sum(1 for c in host_conns if c.get('service') == stats.get('service'))
    
        # Calculate all host-level rates safely
        stats['dst_host_same_srv_rate'] = self._safe_divide(stats['dst_host_srv_count'], stats['dst_host_count'])
        stats['dst_host_diff_srv_rate'] = 1 - stats['dst_host_same_srv_rate']
    
        # Error rates
        total_errors = sum(c.get('wrong_fragment', 0) + c.get('urgent', 0) for c in host_conns)
        stats['dst_host_serror_rate'] = self._safe_divide(total_errors, stats['dst_host_count'])

    def _is_connection_closed(self, pkt) -> bool:
        """Determine if connection is closing"""
        return pkt.haslayer(TCP) and pkt[TCP].flags.F

    def _finalize_features(self, key) -> dict:
        stats = self.connection_stats[key]
        # Ensure all calculations use _safe_divide
        stats['dst_host_srv_diff_host_rate'] = self._safe_divide(
             stats.get('different_host_services', 0), 
             stats['dst_host_srv_count']
             )     
        return self._format_features(stats)

    def _format_features(self, stats: dict) -> dict:
        """Format all 41 NSL-KDD features in required order"""
        return {
        # Basic features
        'duration': float(stats.get('duration', 0)),
        'protocol_type': str(stats.get('protocol_type', 'tcp')),
        'service': str(stats.get('service', 'other')), 
        'flag': str(stats.get('flag', 'OTH')),
        'src_bytes': int(stats.get('src_bytes', 0)),
        'dst_bytes': int(stats.get('dst_bytes', 0)),
        
        # Connection state features
        'land': int(stats.get('land', 0)),
        'wrong_fragment': int(stats.get('wrong_fragment', 0)),
        'urgent': int(stats.get('urgent', 0)),
        'hot': int(stats.get('hot', 0)),
        
        # Authentication features
        'num_failed_logins': stats.get('num_failed_logins', 0),
        'logged_in': stats.get('logged_in', 0),
        
        # Compromise metrics
        'num_compromised': stats.get('num_compromised', 0),
        'root_shell': stats.get('root_shell', 0),
        'su_attempted': stats.get('su_attempted', 0),
        'num_root': stats.get('num_root', 0),
        
        # File/shell operations
        'num_file_creations': stats.get('num_file_creations', 0),
        'num_shells': stats.get('num_shells', 0),
        'num_access_files': stats.get('num_access_files', 0),
        'num_outbound_cmds': stats.get('num_outbound_cmds', 0),
        
        # User context
        'is_host_login': stats.get('is_host_login', 0),
        'is_guest_login': stats.get('is_guest_login', 0),
        
        # Traffic window features
        'count': stats.get('count', 0),
        'srv_count': stats.get('srv_count', 0),
        
        # Error rates
        'serror_rate': stats.get('serror_rate', 0.0),
        'srv_serror_rate': stats.get('srv_serror_rate', 0.0),
        'rerror_rate': stats.get('rerror_rate', 0.0),
        'srv_rerror_rate': stats.get('srv_rerror_rate', 0.0),
        
        # Service distribution
        'same_srv_rate': stats.get('same_srv_rate', 0.0),
        'diff_srv_rate': stats.get('diff_srv_rate', 0.0),
        'srv_diff_host_rate': stats.get('srv_diff_host_rate', 0.0),
        
        # Destination host features
        'dst_host_count': stats.get('dst_host_count', 0),
        'dst_host_srv_count': stats.get('dst_host_srv_count', 0),
        'dst_host_same_srv_rate': stats.get('dst_host_same_srv_rate', 0.0),
        'dst_host_diff_srv_rate': stats.get('dst_host_diff_srv_rate', 0.0),
        'dst_host_same_src_port_rate': stats.get('dst_host_same_src_port_rate', 0.0),
        'dst_host_srv_diff_host_rate': stats.get('dst_host_srv_diff_host_rate', 0.0),
        'dst_host_serror_rate': stats.get('dst_host_serror_rate', 0.0),
        'dst_host_srv_serror_rate': stats.get('dst_host_srv_serror_rate', 0.0),
        'dst_host_rerror_rate': stats.get('dst_host_rerror_rate', 0.0),
        'dst_host_srv_rerror_rate': float(stats.get('dst_host_srv_rerror_rate', 0.0))
        }

    def _handle_features(self, features: dict):
        """Handle extracted features through callback or default"""
        if self.feature_callback:
            self.feature_callback(features)
        else:
            self._default_feature_handler(features)

    def _default_feature_handler(self, features: dict):
        """Default feature handling (override with callback)"""
        print("Extracted Features:")
        for k, v in features.items():
            print(f"{k:>25}: {v}")

    def _get_service(self, pkt) -> str:
        """Map port to service name"""
        if pkt.haslayer(ICMP):
            return 'icmp'
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport
        else:
            return ''
        return self.config['service_map'].get(port, 'other')

    def _get_tcp_flags(self, pkt) -> str:
        """Convert TCP flags to NSL-KDD format"""
        if not pkt.haslayer(TCP):
            return 'OTH'
        # Get flag string like 'SA' or 'F'
        flag_str = pkt[TCP].sprintf('%flags%')
        return self.config['flag_map'].get(flag_str, 'OTH')

    def _get_protocol_type(self, pkt) -> str:
        """Get protocol type from packet"""
        if pkt.haslayer(TCP):
            return 'tcp'
        if pkt.haslayer(UDP):
            return 'udp'
        if pkt.haslayer(ICMP):
            return 'icmp'
        return 'other'
    
    def process_packet(self, pkt_info):
        """
        Synchronously process packet information and return a full NSL-KDD feature vector.
        """
        # 1) Build a synthetic Scapy packet so we can reuse all the update_* methods
        pkt = Ether()/IP(src=pkt_info['ip']['src'], dst=pkt_info['ip']['dst'])
        if pkt_info.get('raw'):
            pkt = pkt/Raw(pkt_info['raw'])

        # 2) Initialize & update stats for this 4-tuple
        key = self._get_connection_key(pkt)
        self._init_connection(pkt, key)
        self._update_basic_features(pkt, key)
        if self.config.get('enable_dpi', False):
            self._update_content_features(pkt, key)
        self._update_traffic_features(key)
        self._update_host_stats(key)

        # 3) Append this connection snapshot to the sliding window
        stats = self.connection_stats[key]
        window_snapshot = {k: stats[k] for k in stats
                           if k not in ('last_100_connections','start_time')}
        stats['last_100_connections'].append(window_snapshot)
        stats['last_100_connections'] = stats['last_100_connections'][-self.config['window_size']:]

        # 4) Finalize & format the *entire* NSL-KDD feature set
        features = self._finalize_features(key)
        features['src_ip'] = pkt_info['ip']['src']
        features['dst_ip'] = pkt_info['ip']['dst']
        return features
    
    def _safe_divide(self, numerator, denominator):
        """Safe division with zero denominator handling"""
        return numerator / denominator if denominator != 0 else 0.0

