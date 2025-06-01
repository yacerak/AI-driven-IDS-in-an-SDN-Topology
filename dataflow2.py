import pandas as pd
import random
import time
import os
from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP
import numpy as np
import threading
from collections import deque

# Configuration
BUFFER_SIZE = 100  # Number of log entries to buffer before writing
PACKETS_PER_SECOND = 100  # Average packets/sec for timing
HOST_NETWORK = "10.0.0.0/24"  # For generating multiple hosts

# Dataset features and parameters
features = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
          "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells",
          "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
          "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count", 
          "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
          "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]


# Generate IP pool
MAC_PREFIX = "02:00:00:"
ip_pool = {
    ip: (MAC_PREFIX + f"{i:02x}:{i%0xff:02x}:{i//0xff:02x}")
    for i, ip in enumerate([f"10.0.0.{x}" for x in range(1, 254)])
}

host_ips = [ip for ip in ip_pool.keys() if ip != "10.0.0.1"]
src_ips = list(ip_pool.keys())

test21 = 'KDDTest-21.txt'

# Load dataset
test_21 = pd.read_csv(test21, names=features) 
test_21.drop(['difficulty'], axis=1, inplace=True)

# Complete service to port mapping
service_to_port = {
    'http': 80, 'smtp': 25, 'finger': 79, 'domain_u': 53, 'auth': 113,
    'telnet': 23, 'ftp': 21, 'eco_i': 2050, 'ntp_u': 123, 'ecr_i': 2674,
    'other': None, 'private': None, 'pop_3': 110, 'ftp_data': 20, 'rje': 77,
    'time': 37, 'mtp': 1911, 'link': 245, 'remote_job': 71, 'gopher': 70,
    'ssh': 22, 'name': 42, 'whois': 43, 'domain': 53, 'login': 513,
    'imap4': 143, 'daytime': 13, 'ctf': 84, 'nntp': 119, 'shell': 514,
    'IRC': 194, 'nnsp': 433, 'http_443': 443, 'exec': 512, 'printer': 515,
    'efs': 520, 'courier': 530, 'uucp': 540, 'klogin': 543, 'kshell': 544,
    'echo': 7, 'discard': 9, 'systat': 11, 'supdup': 95, 'iso_tsap': 102,
    'hostnames': 101, 'csnet_ns': 105, 'pop_2': 109, 'sunrpc': 111,
    'uucp_path': 117, 'netbios_ns': 137, 'netbios_ssn': 139, 'netbios_dgm': 138,
    'sql_net': 150, 'vmnet': 175, 'bgp': 179, 'Z39_50': 210, 'ldap': 389,
    'netstat': 15, 'urh_i': 5000, 'X11': 6000, 'urp_i': 5001, 'pm_dump': 5002,
    'tftp_u': 69, 'tim_i': 525, 'red_i': 5003, 'icmp': None, 'http_2784': 2784,
    'harvest': 2813, 'aol': 5190, 'http_8001': 8001
}

# Complete flag mapping to TCP flags
flag_mapping = {
    'OTH': '',        # Other (established connection)
    'RSTOS0': 'RA',   # RST-ACK
    'SF': 'SF',       # SYN-FIN
    'SH': 'S',        # SYN
    'RSTO': 'R',      # RST
    'S2': 'S',        # SYN
    'S1': 'SA',       # SYN-ACK
    'REJ': 'R',       # RST
    'S3': 'S',        # SYN
    'RSTR': 'RA',     # RST-ACK
    'S0': 'S'         # SYN
}


# Initialize logging queue and buffer
log_queue = deque()
buffer_lock = threading.Lock()
stop_logging = threading.Event()

# Service/port mappings and other constants remain the same
# [Previous service_to_port and flag_mapping dictionaries remain unchanged]

def log_writer():
    """Background thread for writing logs"""
    while not stop_logging.is_set() or log_queue:
        with buffer_lock:
            if len(log_queue) >= BUFFER_SIZE or (stop_logging.is_set() and log_queue):
                batch = [log_queue.popleft() for _ in range(min(BUFFER_SIZE, len(log_queue)))]
                with open("true_labels.csv", "a") as f:
                    f.writelines(batch)
        time.sleep(0.1)

def get_dst_port(service):
    """Get destination port with validation"""
    port = service_to_port.get(service)
    if port is None or not (0 <= port <= 65535):
        # Generate a valid port even for unknown services
        return random.randint(0, 65535)  # Include entire valid range
    return port

# Update MAC handling in simulation functions
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def get_mac(ip):
    """Get MAC from pool or return broadcast address"""
    return ip_pool.get(ip, BROADCAST_MAC)

def simulate_tcp_flow(row):
    """Simulate complete TCP flow with ARP resolution"""
    try:
        # Generate endpoints
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(host_ips) if row['land'] == 0 else src_ip
        src_mac = ip_pool[src_ip]
        
        # ARP Resolution Simulation
        arp_request = Ether(dst=BROADCAST_MAC, src=src_mac)/\
                      ARP(pdst=dst_ip, psrc=src_ip)
        send(arp_request, verbose=0)
        time.sleep(0.1)  # Simulate ARP response delay
        
        # Get destination MAC (simulate ARP response)
        dst_mac = get_mac(dst_ip)  # Use actual MAC if known, else broadcast

        # TCP Handshake with MAC resolution
        syn = Ether(src=src_mac, dst=dst_mac)/\
              IP(src=src_ip, dst=dst_ip)/\
              TCP(sport=random.randint(1024, 65535),
                  dport=get_dst_port(row['service']),
                  flags='S',
                  seq=random.randint(0, 2**32-1))
        
        # Send SYN and handle response
        syn_ack = sr1(syn, timeout=1, verbose=0)
        
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & 0x12:  # SYN-ACK
            # Complete handshake with actual MAC
            ack = Ether(src=src_mac, dst=syn_ack[Ether].src)/\
                  IP(src=src_ip, dst=dst_ip)/\
                  TCP(sport=syn.sport,
                      dport=syn.dport,
                      flags='A',
                      seq=syn.seq + 1,
                      ack=syn_ack.seq + 1)
            send(ack, verbose=0)

        # --- Data Transfer Phase ---
        # Client to server data
        if row['src_bytes'] > 0:
            client_data = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='PA', 
                seq=ack.seq, ack=syn_ack.seq+1)/Raw(load=os.urandom(row['src_bytes']))
            send(client_data, verbose=0)
            time.sleep(random.expovariate(PACKETS_PER_SECOND))

        # Server to client data
        if row['dst_bytes'] > 0:
            server_data = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='PA', 
                seq=syn_ack.seq+1, ack=client_data.seq+len(client_data[Raw]) if row['src_bytes'] > 0 else syn_ack.seq+1)/Raw(load=os.urandom(row['dst_bytes']))
            send(server_data, verbose=0)
            time.sleep(random.expovariate(PACKETS_PER_SECOND))

        # --- Connection Termination ---
        # FIN from client
        fin = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='FA', 
            seq=client_data.seq+len(client_data[Raw]) if row['src_bytes'] > 0 else ack.seq, 
            ack=server_data.seq+len(server_data[Raw]) if row['dst_bytes'] > 0 else syn_ack.seq+1)
        send(fin, verbose=0)
        time.sleep(random.expovariate(PACKETS_PER_SECOND))

        # ACK from server
        fin_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='A', 
            seq=server_data.seq+len(server_data[Raw]) if row['dst_bytes'] > 0 else syn_ack.seq+1, 
            ack=fin.seq+1)
        send(fin_ack, verbose=0)
        time.sleep(random.expovariate(PACKETS_PER_SECOND))

    except Exception as e:
        print(f"Error in TCP flow simulation: {str(e)}")

def simulate_udp_flow(row):
    """Simulate UDP flow with bidirectional traffic"""
    try:
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(host_ips)
        src_mac = ip_pool[src_ip]
        dst_mac = ip_pool[dst_ip]
        
        # Generate ports
        src_port = random.randint(1024, 65535)
        dst_port = get_dst_port(row['service'])
        
        pkt = Ether(src=src_mac, dst=dst_mac)/\
              IP(src=src_ip, dst=dst_ip)/\
              UDP(sport=src_port, dport=dst_port)/\
              Raw(load=os.urandom(row['src_bytes']))
              
    except Exception as e:
        print(f"Error in UDP flow simulation: {str(e)}")

def simulate_icmp_flow(row):
    """Simulate ICMP echo request/reply pattern"""
    try:
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(host_ips)
        
        request = Ether(src=ip_pool[src_ip], dst=get_mac(dst_ip))/\
                  IP(src=src_ip, dst=dst_ip)/\
                  ICMP()/\
                  Raw(load=os.urandom(row['src_bytes']))
        
        send(request, verbose=0)

    except Exception as e:
        print(f"ICMP error: {str(e)}")
        
def send_traffic():
    # Start logging thread
    log_thread = threading.Thread(target=log_writer)
    log_thread.start()

    # Create header if file doesn't exist
    if not os.path.exists("true_labels.csv"):
        with open("true_labels.csv", "w") as f:
            f.write("row_id,true_label\n")

    try:
        # Weight sampling towards attacks (adjust ratio as needed)
        attack_weight = 0.8  # 80% attack samples
        weights = np.where(test_21['label'] == 'normal', 1 - attack_weight, attack_weight)

        while True:
            # Weighted sampling
            row = test_21.sample(1, weights=weights).iloc[0]
            row_id = row.name
            true_label = row['label']

            # Buffer log entry
            with buffer_lock:
                log_queue.append(f"{row_id},{true_label}\n")

            # Simulate appropriate flow
            {
                'tcp': simulate_tcp_flow,
                'udp': simulate_udp_flow,
                'icmp': simulate_icmp_flow
            }[row['protocol_type']](row)

    except KeyboardInterrupt:
        print("\nStopping traffic generation...")
        stop_logging.set()
        log_thread.join()
        print("Flushing remaining logs...")
        with open("true_labels.csv", "a") as f:
            while log_queue:
                f.write(log_queue.popleft())
        print("Clean shutdown complete.")

if __name__ == "__main__":
    send_traffic()
