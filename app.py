import pandas as pd
import numpy as np
from flask import Flask, request, jsonify, g
from scapy.all import sniff, IP, TCP, UDP, get_working_ifaces, get_if_list, conf, Raw
from tensorflow.keras.models import load_model
import joblib
import threading
import socket
import struct
import logging
from collections import defaultdict
from datetime import datetime
import os
import netifaces
import sys

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load model and preprocessors
try:
    model = load_model('model.keras')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    # Log the possible labels from the label encoder
    logging.info(f"Label encoder classes: {label_encoder.classes_}")
except Exception as e:
    logging.error(f"Failed to load model or preprocessors: {e}")
    raise

# Define features and columns to drop
FEATURES = [
    'unnamed_0', 'flow_id', 'source_ip', 'source_port', 'destination_ip', 'destination_port',
    'protocol', 'timestamp', 'flow_duration', 'total_fwd_packets', 'total_backward_packets',
    'total_length_of_fwd_packets', 'total_length_of_bwd_packets', 'fwd_packet_length_max',
    'fwd_packet_length_min', 'fwd_packet_length_mean', 'fwd_packet_length_std',
    'bwd_packet_length_max', 'bwd_packet_length_min', 'bwd_packet_length_mean',
    'bwd_packet_length_std', 'flow_bytess', 'flow_packetss', 'flow_iat_mean',
    'flow_iat_std', 'flow_iat_max', 'flow_iat_min', 'fwd_iat_total', 'fwd_iat_mean',
    'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min', 'bwd_iat_total', 'bwd_iat_mean',
    'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min', 'fwd_psh_flags', 'bwd_psh_flags',
    'fwd_urg_flags', 'bwd_urg_flags', 'fwd_header_length', 'bwd_header_length',
    'fwd_packetss', 'bwd_packetss', 'min_packet_length', 'max_packet_length',
    'packet_length_mean', 'packet_length_std', 'packet_length_variance',
    'fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count',
    'ack_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
    'downup_ratio', 'average_packet_size', 'avg_fwd_segment_size',
    'avg_bwd_segment_size', 'fwd_header_length1', 'fwd_avg_bytesbulk',
    'fwd_avg_packetsbulk', 'fwd_avg_bulk_rate', 'bwd_avg_bytesbulk',
    'bwd_avg_packetsbulk', 'bwd_avg_bulk_rate', 'subflow_fwd_packets',
    'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes',
    'init_win_bytes_forward', 'init_win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'active_mean', 'active_std', 'active_max',
    'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min',
    'simillarhttp', 'inbound', 'label', 'unique_source_ips', 'packet_rate',
    'http_request_rate'  # New feature for HTTP flood detection
]

DROP_COLS = [
    'unnamed_0', 'flow_id', 'source_ip', 'destination_ip',
    'source_port', 'destination_port', 'timestamp', 'protocol'
]

# Global variables for packet capture and banned IPs
captured_packets = []
capture_lock = threading.Lock()
banned_ips = set()  # Temporary in-memory storage for banned IPs

def ip_to_int(ip):
    try:
        return int(struct.unpack("!I", socket.inet_aton(ip))[0])
    except:
        logging.warning(f"Invalid IP address: {ip}")
        return 0

def get_local_ip():
    """Get the machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        logging.error(f"Failed to get local IP: {e}")
        return "127.0.0.1"

def check_npcap():
    """Check if Npcap/WinPcap is available for Scapy."""
    try:
        conf.ifaces
        return True
    except Exception as e:
        logging.error(f"Npcap/WinPcap not detected: {e}")
        return False

def get_active_interface(client_ip):
    """Get a valid network interface, with special handling for localhost."""
    try:
        interfaces = get_working_ifaces()
        for iface in interfaces:
            if iface.is_valid():
                logging.info(f"Selected interface: {iface.name}")
                return iface.name
    except Exception as e:
        logging.error(f"Failed to get working interfaces: {e}")
    
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                iface_ip = addrs[netifaces.AF_INET][0].get('addr', 'No IP')
                logging.info(f"Fallback interface: {iface}, IP: {iface_ip}")
                if client_ip in ["127.0.0.1", "localhost"] and "loopback" in iface.lower():
                    return iface
                if iface_ip == client_ip:
                    return iface
                return iface
    except Exception as e:
        logging.error(f"Failed to get fallback interface: {e}")
    
    raise Exception("No valid network interface found")

def check_permissions():
    """Check if the script has sufficient permissions for packet capture."""
    if os.name == 'posix' and os.geteuid() != 0:
        return False
    return True

def packet_callback(packet):
    with capture_lock:
        if IP in packet:
            # Check for HTTP traffic
            if TCP in packet and packet[TCP].dport in [80, 5000]:  # Flask runs on 5000
                if Raw in packet:
                    payload = packet[Raw].load.decode(errors='ignore')
                    if any(method in payload for method in ['GET', 'POST', 'HEAD']):
                        logging.debug(f"HTTP packet detected: {payload.splitlines()[0]}")
            captured_packets.append(packet)

def capture_packets(interface, client_ip, duration=30):
    global captured_packets
    captured_packets = []
    if client_ip in ["127.0.0.1", "localhost"]:
        filter_str = "tcp or udp"
        logging.info(f"Client IP is localhost, using broader filter: {filter_str}")
    else:
        filter_str = f"host {client_ip}"
        logging.info(f"Starting packet capture for {client_ip} on {interface} for {duration} seconds with filter: {filter_str}")
    
    try:
        sniff(iface=interface, prn=packet_callback, filter=filter_str, timeout=duration, store=False)
    except Exception as e:
        logging.error(f"Packet capture failed: {e}")
    logging.info(f"Capture complete. {len(captured_packets)} packets captured.")

def extract_features(packets, client_ip):
    if not packets:
        logging.warning("No packets provided for feature extraction")
        return pd.DataFrame()

    flows = defaultdict(lambda: {
        'timestamps': [], 'fwd_packets': [], 'bwd_packets': [],
        'fwd_lengths': [], 'bwd_lengths': [], 'flags': defaultdict(int),
        'source_ips': set(), 'http_requests': []
    })
    
    for pkt in packets:
        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        flow_key = (src_ip, dst_ip, pkt.sport if TCP in pkt or UDP in pkt else 0,
                    pkt.dport if TCP in pkt or UDP in pkt else 0,
                    pkt.proto)
        
        flow = flows[flow_key]
        flow['timestamps'].append(pkt.time)
        flow['source_ips'].add(src_ip)
        pkt_len = len(pkt)
        
        # Detect HTTP requests
        is_http = False
        if TCP in pkt and pkt[TCP].dport in [80, 5000]:  # Check Flask port
            if Raw in pkt:
                payload = pkt[Raw].load.decode(errors='ignore')
                if any(method in payload for method in ['GET', 'POST', 'HEAD']):
                    flow['http_requests'].append(pkt.time)
                    is_http = True
        
        if src_ip == client_ip:
            flow['fwd_packets'].append(pkt)
            flow['fwd_lengths'].append(pkt_len)
            if TCP in pkt:
                tcp = pkt[TCP]
                flow['flags']['fwd_psh'] += 1 if 'P' in tcp.flags else 0
                flow['flags']['fwd_urg'] += 1 if 'U' in tcp.flags else 0
                flow['flags']['fin'] += 1 if 'F' in tcp.flags else 0
                flow['flags']['syn'] += 1 if 'S' in tcp.flags else 0
                flow['flags']['rst'] += 1 if 'R' in tcp.flags else 0
                flow['flags']['ack'] += 1 if 'A' in tcp.flags else 0
        else:
            flow['bwd_packets'].append(pkt)
            flow['bwd_lengths'].append(pkt_len)
            if TCP in pkt:
                tcp = pkt[TCP]
                flow['flags']['bwd_psh'] += 1 if 'P' in tcp.flags else 0
                flow['flags']['bwd_urg'] += 1 if 'U' in tcp.flags else 0
    
    data = []
    for flow_key, flow in flows.items():
        src_ip, dst_ip, src_port, dst_port, proto = flow_key
        timestamps = sorted(flow['timestamps'])
        flow_duration = (max(timestamps) - min(timestamps)) * 1e6 if timestamps else 0
        
        fwd_lengths = flow['fwd_lengths']
        bwd_lengths = flow['bwd_lengths']
        total_fwd_packets = len(flow['fwd_packets'])
        total_bwd_packets = len(flow['bwd_packets'])
        total_packets = total_fwd_packets + total_bwd_packets
        
        iat = np.diff(timestamps) * 1e6 if len(timestamps) > 1 else [0]
        
        # DDoS-specific features
        packet_rate = total_packets / (flow_duration / 1e6) if flow_duration else 0
        unique_source_ips = len(flow['source_ips'])
        
        # HTTP-specific features
        http_timestamps = sorted(flow['http_requests'])
        http_request_count = len(http_timestamps)
        http_request_rate = http_request_count / (flow_duration / 1e6) if flow_duration else 0
        simillarhttp = 1 if http_request_count > 0 else 0
        
        row = {
            'unnamed_0': 0,
            'flow_id': f'{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}',
            'source_ip': ip_to_int(src_ip),
            'source_port': src_port,
            'destination_ip': ip_to_int(dst_ip),
            'destination_port': dst_port,
            'protocol': proto,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_backward_packets': total_bwd_packets,
            'total_length_of_fwd_packets': sum(fwd_lengths),
            'total_length_of_bwd_packets': sum(bwd_lengths),
            'fwd_packet_length_max': max(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_min': min(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_mean': np.mean(fwd_lengths) if fwd_lengths else 0,
            'fwd_packet_length_std': np.std(fwd_lengths) if fwd_lengths else 0,
            'bwd_packet_length_max': max(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_min': min(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_mean': np.mean(bwd_lengths) if bwd_lengths else 0,
            'bwd_packet_length_std': np.std(bwd_lengths) if bwd_lengths else 0,
            'flow_bytess': (sum(fwd_lengths) + sum(bwd_lengths)) / (flow_duration / 1e6) if flow_duration else 0,
            'flow_packetss': packet_rate,
            'flow_iat_mean': np.mean(iat) if len(iat) > 0 else 0,
            'flow_iat_std': np.std(iat) if len(iat) > 0 else 0,
            'flow_iat_max': max(iat) if len(iat) > 0 else 0,
            'flow_iat_min': min(iat) if len(iat) > 0 else 0,
            'fwd_iat_total': sum(iat) if len(iat) > 0 else 0,
            'fwd_iat_mean': np.mean(iat) if len(iat) > 0 else 0,
            'fwd_iat_std': np.std(iat) if len(iat) > 0 else 0,
            'fwd_iat_max': max(iat) if len(iat) > 0 else 0,
            'fwd_iat_min': min(iat) if len(iat) > 0 else 0,
            'bwd_iat_total': sum(iat) if len(iat) > 0 else 0,
            'bwd_iat_mean': np.mean(iat) if len(iat) > 0 else 0,
            'bwd_iat_std': np.std(iat) if len(iat) > 0 else 0,
            'bwd_iat_max': max(iat) if len(iat) > 0 else 0,
            'bwd_iat_min': min(iat) if len(iat) > 0 else 0,
            'fwd_psh_flags': flow['flags']['fwd_psh'],
            'bwd_psh_flags': flow['flags']['bwd_psh'],
            'fwd_urg_flags': flow['flags']['fwd_urg'],
            'bwd_urg_flags': flow['flags']['bwd_urg'],
            'fwd_header_length': sum(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt),
            'bwd_header_length': sum(pkt[IP].ihl * 4 for pkt in flow['bwd_packets'] if IP in pkt),
            'fwd_packetss': total_fwd_packets / (flow_duration / 1e6) if flow_duration else 0,
            'bwd_packetss': total_bwd_packets / (flow_duration / 1e6) if flow_duration else 0,
            'min_packet_length': min(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'max_packet_length': max(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_mean': np.mean(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_std': np.std(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'packet_length_variance': np.var(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'fin_flag_count': flow['flags']['fin'],
            'syn_flag_count': flow['flags']['syn'],
            'rst_flag_count': flow['flags']['rst'],
            'psh_flag_count': flow['flags']['fwd_psh'] + flow['flags']['bwd_psh'],
            'ack_flag_count': flow['flags']['ack'],
            'urg_flag_count': flow['flags']['fwd_urg'] + flow['flags']['bwd_urg'],
            'cwe_flag_count': 0,
            'ece_flag_count': 0,
            'downup_ratio': total_bwd_packets / total_fwd_packets if total_fwd_packets else 0,
            'average_packet_size': np.mean(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0,
            'avg_fwd_segment_size': np.mean(fwd_lengths) if fwd_lengths else 0,
            'avg_bwd_segment_size': np.mean(bwd_lengths) if bwd_lengths else 0,
            'fwd_header_length1': sum(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt),
            'fwd_avg_bytesbulk': 0,
            'fwd_avg_packetsbulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytesbulk': 0,
            'bwd_avg_packetsbulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': total_fwd_packets,
            'subflow_fwd_bytes': sum(fwd_lengths),
            'subflow_bwd_packets': total_bwd_packets,
            'subflow_bwd_bytes': sum(bwd_lengths),
            'init_win_bytes_forward': flow['fwd_packets'][0][TCP].window if flow['fwd_packets'] and TCP in flow['fwd_packets'][0] else 0,
            'init_win_bytes_backward': flow['bwd_packets'][0][TCP].window if flow['bwd_packets'] and TCP in flow['bwd_packets'][0] else 0,
            'act_data_pkt_fwd': total_fwd_packets,
            'min_seg_size_forward': min(pkt[IP].ihl * 4 for pkt in flow['fwd_packets'] if IP in pkt) if flow['fwd_packets'] else 0,
            'active_mean': 0,
            'active_std': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0,
            'simillarhttp': simillarhttp,
            'inbound': 1 if src_ip == client_ip else 0,
            'label': 0,
            'unique_source_ips': unique_source_ips,
            'packet_rate': packet_rate,
            'http_request_rate': http_request_rate
        }
        data.append(row)

    df = pd.DataFrame(data)
    if df.empty:
        logging.warning("Feature DataFrame is empty")
        return df

    for feature in FEATURES:
        if feature not in df.columns and feature != 'label':
            df[feature] = 0
    
    df = df.drop(columns=[col for col in DROP_COLS if col in df.columns], errors='ignore')
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace(r'[^\w]', '', regex=True)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    numeric_cols = df.select_dtypes(include='number').columns
    df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
    df = df.apply(pd.to_numeric, errors='coerce').fillna(0)
    
    logging.debug(f"Extracted features DataFrame:\n{df}")
    return df

# Check for Npcap at startup
if not check_npcap():
    logging.error("Npcap is not installed or not properly configured. Please install Npcap from https://npcap.com/ and ensure it is in WinPcap API-compatible mode.")
    sys.exit(1)

@app.before_request
def before_request():
    try:
        client_ip = request.remote_addr
        logging.info(f"Raw client IP from request.remote_addr: {client_ip}")
        if client_ip in banned_ips:
            logging.warning(f"Blocked request from banned IP: {client_ip}")
            return jsonify({
                'status': 'error',
                'message': 'Your IP is temporarily banned due to suspicious activity'
            }), 403

        if not check_permissions():
            logging.error("Insufficient permissions for packet capture. Run as Administrator on Windows.")
            g.client_ip = None
            g.packets = []
            return

        if client_ip == "127.0.0.1":
            client_ip = get_local_ip()
            logging.info(f"Client IP is localhost, using local IP: {client_ip}")

        interface = get_active_interface(client_ip)
        
        capture_thread = threading.Thread(target=capture_packets, args=(interface, client_ip, 30))
        capture_thread.start()
        capture_thread.join()
        
        g.client_ip = client_ip
        g.packets = captured_packets
        logging.info(f"Stored client IP: {g.client_ip}, Packets captured: {len(g.packets)}")
    except Exception as e:
        logging.error(f"Error in before_request: {e}")
        g.client_ip = None
        g.packets = []

@app.route('/')
def index():
    try:
        client_ip = getattr(g, 'client_ip', None)
        packets = getattr(g, 'packets', [])
        
        if not client_ip or not packets:
            logging.error(f"Failed to proceed: client_ip={client_ip}, packets={len(packets)}")
            return jsonify({
                'status': 'error',
                'message': 'Failed to capture packets or identify client IP'
            }), 200

        features_df = extract_features(packets, client_ip)
        if features_df.empty:
            logging.warning("No features extracted from packets")
            return jsonify({
                'status': 'error',
                'message': 'No features extracted from packets'
            }), 200

        features_scaled = scaler.transform(features_df)
        predictions = model.predict(features_scaled)
        decoded_predictions = label_encoder.inverse_transform(predictions.argmax(axis=1))
        
        logging.info(f"Raw predictions (probabilities):\n{predictions}")
        logging.info(f"Decoded predictions: {decoded_predictions}")
        
        results = []
        for i, pred in enumerate(decoded_predictions):
            src_ip = socket.inet_ntoa(struct.pack('>I', int(features_df.iloc[i]['source_ip'])))
            results.append({'source_ip': src_ip, 'prediction': pred})
        
        # Check for attack (including HTTP flood)
        is_attack = any(pred.lower() in ['attack', 'malicious', 'intrusion', 'ddos', 'http_flood'] for pred in decoded_predictions)
        
        # Rule-based HTTP flood detection
        http_request_rate = features_df['http_request_rate'].iloc[0] if 'http_request_rate' in features_df else 0
        unique_source_ips = features_df['unique_source_ips'].iloc[0] if 'unique_source_ips' in features_df else 1
        rule_based_http_flood = http_request_rate > 100 or (http_request_rate > 50 and unique_source_ips > 5)  # Adjust thresholds
        logging.info(f"Rule-based HTTP flood check: http_request_rate={http_request_rate}, unique_source_ips={unique_source_ips}, detected={rule_based_http_flood}")
        
        is_attack = is_attack or rule_based_http_flood
        
        if is_attack:
            logging.warning(f"!!! Potential cyberattack detected from IP: {client_ip} !!!")
            banned_ips.add(client_ip)
            logging.info(f"Temporarily banned IP: {client_ip}")

        return jsonify({
            'status': 'success',
            'client_ip': client_ip,
            'predictions': results,
            'is_attack': is_attack
        }), 200
    
    except Exception as e:
        logging.error(f"Index route error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/debug_interfaces', methods=['GET'])
def debug_interfaces():
    try:
        interfaces = netifaces.interfaces()
        iface_details = []
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'No IP')
            iface_details.append({'interface': iface, 'ip': ip})
        return jsonify({
            'status': 'success',
            'interfaces': iface_details
        }), 200
    except Exception as e:
        logging.error(f"Debug interfaces error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/banned_ips', methods=['GET'])
def get_banned_ips():
    try:
        return jsonify({
            'status': 'success',
            'banned_ips': list(banned_ips)
        }), 200
    except Exception as e:
        logging.error(f"Banned IPs endpoint error: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
