from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import joblib
import logging
from datetime import datetime
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
import threading

app = Flask(__name__)

# Configure logging 2
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load model and preprocessors
try:
    model = load_model('my_model.keras')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    logging.info(f"Label encoder classes: {label_encoder.classes_}")
except Exception as e:
    logging.error(f"Failed to load model or preprocessors: {e}")
    raise

# Define features (aligned with training data)
FEATURES = [
    'flow_duration', 'total_fwd_packets', 'total_backward_packets',
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
    'inbound'
]

DROP_COLS = [
    'unnamed_0', 'flow_id', 'source_ip', 'destination_ip',
    'source_port', 'destination_port', 'timestamp', 'protocol',
    'label', 'attack_type'
]

# Store request timestamps for each IP
request_timestamps = defaultdict(list)
# Store traffic samples for each IP (IP -> list of samples)
traffic_samples_by_ip = defaultdict(list)
# Store analysis history for dashboard
analysis_history = []
# Store raw network packets for processing
network_data = {
    'packets': [],
    'timestamps': [],
    'source_ips': set(),
    'last_processed': time.time()
}

def preprocess_data(data_df):
    """Preprocess a DataFrame of traffic data for model prediction"""
    try:
        # Ensure all required features are present
        for feature in FEATURES:
            if feature not in data_df.columns:
                data_df[feature] = 0
        
        # Drop unnecessary columns
        data_df = data_df.drop(columns=[col for col in DROP_COLS if col in data_df.columns], errors='ignore')
        
        # Scale numerical features
        numerical_cols = data_df.select_dtypes(include=['int64', 'float64']).columns
        if numerical_cols.empty:
            raise ValueError("No numerical columns to scale.")
        
        logging.info(f"Columns before scaling: {data_df.columns.tolist()}")
        data_df[numerical_cols] = scaler.transform(data_df[numerical_cols])
        
        return data_df
    except Exception as e:
        logging.error(f"Error in preprocessing: {e}")
        raise

def analyze_traffic(data_df):
    """Analyze aggregated traffic data using the loaded model"""
    try:
        # Aggregate the data by calculating the mean of numerical features
        aggregated_data = data_df.select_dtypes(include=['int64', 'float64']).mean().to_dict()
        aggregated_df = pd.DataFrame([aggregated_data])
        
        # Preprocess the aggregated data
        processed_data = preprocess_data(aggregated_df)
        
        # Make prediction
        prediction = model.predict(processed_data)
        predicted_class = label_encoder.inverse_transform([np.argmax(prediction[0])])[0]
        confidence = np.max(prediction[0])
        
        return predicted_class, confidence
    except Exception as e:
        logging.error(f"Error in traffic analysis: {e}")
        return "Error", 0.0

def calculate_request_rate(ip_address):
    """Calculate the request rate for a given IP address"""
    current_time = time.time()
    request_timestamps[ip_address] = [t for t in request_timestamps[ip_address] if current_time - t < 60]
    return len(request_timestamps[ip_address]) / 60.0

def check_time_interval(ip_address, current_time):
    """Check if the time interval between requests is between 0.1 and 1.5 seconds"""
    timestamps = request_timestamps[ip_address]
    if len(timestamps) < 2:
        return True  # Not enough data to compare, include by default
    
    last_time = timestamps[-2]
    interval = current_time - last_time
    return 0.1 <= interval <= 1.5

def packet_callback(packet):
    """Callback function to process captured packets"""
    if IP in packet:
        current_time = time.time()
        network_data['packets'].append(packet)
        network_data['timestamps'].append(current_time)
        network_data['source_ips'].add(packet[IP].src)

def process_network_data():
    """Process captured network data and calculate features"""
    current_time = time.time()
    # Process data every 5 seconds
    if current_time - network_data['last_processed'] < 5:
        return None

    packets = network_data['packets']
    timestamps = network_data['timestamps']
    source_ips = network_data['source_ips']

    if not packets:
        return None

    # Calculate features
    total_packets = len(packets)
    time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    flow_iat_mean = np.mean(time_diffs) if time_diffs else 0
    flow_iat_std = np.std(time_diffs) if time_diffs else 0
    flow_iat_max = max(time_diffs) if time_diffs else 0
    flow_iat_min = min(time_diffs) if time_diffs else 0
    packet_lengths = [len(pkt) for pkt in packets]
    total_length = sum(packet_lengths)
    packet_length_mean = np.mean(packet_lengths) if packet_lengths else 0
    packet_length_std = np.std(packet_lengths) if packet_lengths else 0
    packet_rate = total_packets / (current_time - network_data['last_processed'])

    # Separate TCP and UDP packets
    tcp_packets = [pkt for pkt in packets if TCP in pkt]
    udp_packets = [pkt for pkt in packets if UDP in pkt]
    total_tcp_packets = len(tcp_packets)
    total_udp_packets = len(udp_packets)

    # Determine dominant protocol
    protocol = 6 if total_tcp_packets >= total_udp_packets else 17  # 6 for TCP, 17 for UDP

    # Reset data
    network_data['packets'] = []
    network_data['timestamps'] = []
    network_data['source_ips'] = set()
    network_data['last_processed'] = current_time

    return {
        'protocol': protocol,
        'flow_duration': (current_time - timestamps[0]) * 1000 if timestamps else 1000,
        'total_fwd_packets': total_packets,
        'total_backward_packets': 0,
        'total_length_of_fwd_packets': total_length,
        'total_length_of_bwd_packets': 0,
        'fwd_packet_length_max': max(packet_lengths) if packet_lengths else 0,
        'fwd_packet_length_min': min(packet_lengths) if packet_lengths else 0,
        'fwd_packet_length_mean': packet_length_mean,
        'fwd_packet_length_std': packet_length_std,
        'bwd_packet_length_max': 0,
        'bwd_packet_length_min': 0,
        'bwd_packet_length_mean': 0,
        'bwd_packet_length_std': 0,
        'flow_packetss': packet_rate,
        'flow_iat_mean': flow_iat_mean,
        'flow_iat_std': flow_iat_std,
        'flow_iat_max': flow_iat_max,
        'flow_iat_min': flow_iat_min,
        'fwd_packetss': packet_rate,
        'bwd_packetss': 0
    }

def start_sniffing():
    """Start sniffing network traffic in a separate thread"""
    sniff(prn=packet_callback, store=False, filter="ip", stop_filter=lambda x: False)

@app.route('/')
def index():
    try:
        ip_address = request.remote_addr
        current_time = datetime.now()
        current_timestamp = time.time()
        
        # Add timestamp to request_timestamps
        request_timestamps[ip_address].append(current_timestamp)
        
        # Check time interval between requests (0.1 - 1.5 seconds)
        if not check_time_interval(ip_address, current_timestamp):
            # If interval is not in range, skip adding this sample but still return a response
            result, confidence = "Interval outside range (0.1-1.5s)", 0.0
            is_attack = False
        else:
            # Calculate request rate for HTTP flood detection
            http_request_rate = calculate_request_rate(ip_address)
            
            # Collect traffic data from HTTP request
            content_length = int(request.headers.get('Content-Length', 0))
            user_agent = request.headers.get('User-Agent', '')
            
            # Get network data features
            network_features = process_network_data() or {}

            # Create traffic data sample
            traffic_data = {
                'flow_duration': network_features.get('flow_duration', 1000),
                'total_fwd_packets': network_features.get('total_fwd_packets', 1),
                'total_backward_packets': network_features.get('total_backward_packets', 1),
                'total_length_of_fwd_packets': network_features.get('total_length_of_fwd_packets', content_length),
                'total_length_of_bwd_packets': network_features.get('total_length_of_bwd_packets', 0),
                'fwd_packet_length_max': network_features.get('fwd_packet_length_max', content_length),
                'fwd_packet_length_min': network_features.get('fwd_packet_length_min', content_length),
                'fwd_packet_length_mean': network_features.get('fwd_packet_length_mean', content_length),
                'fwd_packet_length_std': network_features.get('fwd_packet_length_std', 0),
                'bwd_packet_length_max': network_features.get('bwd_packet_length_max', 0),
                'bwd_packet_length_min': network_features.get('bwd_packet_length_min', 0),
                'bwd_packet_length_mean': network_features.get('bwd_packet_length_mean', 0),
                'bwd_packet_length_std': network_features.get('bwd_packet_length_std', 0),
                'flow_bytess': 0,
                'flow_packetss': network_features.get('flow_packetss', 0),
                'flow_iat_mean': network_features.get('flow_iat_mean', 0),
                'flow_iat_std': network_features.get('flow_iat_std', 0),
                'flow_iat_max': network_features.get('flow_iat_max', 0),
                'flow_iat_min': network_features.get('flow_iat_min', 0),
                'fwd_iat_total': 0,
                'fwd_iat_mean': 0,
                'fwd_iat_std': 0,
                'fwd_iat_max': 0,
                'fwd_iat_min': 0,
                'bwd_iat_total': 0,
                'bwd_iat_mean': 0,
                'bwd_iat_std': 0,
                'bwd_iat_max': 0,
                'bwd_iat_min': 0,
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'bwd_urg_flags': 0,
                'fwd_header_length': 0,
                'bwd_header_length': 0,
                'fwd_packetss': network_features.get('fwd_packetss', 0),
                'bwd_packetss': network_features.get('bwd_packetss', 0),
                'min_packet_length': network_features.get('fwd_packet_length_min', content_length),
                'max_packet_length': network_features.get('fwd_packet_length_max', content_length),
                'packet_length_mean': network_features.get('fwd_packet_length_mean', content_length),
                'packet_length_std': network_features.get('fwd_packet_length_std', 0),
                'packet_length_variance': 0,
                'fin_flag_count': 0,
                'syn_flag_count': 0,
                'rst_flag_count': 0,
                'psh_flag_count': 0,
                'ack_flag_count': 0,
                'urg_flag_count': 0,
                'cwe_flag_count': 0,
                'ece_flag_count': 0,
                'downup_ratio': 0,
                'average_packet_size': network_features.get('fwd_packet_length_mean', content_length),
                'avg_fwd_segment_size': network_features.get('fwd_packet_length_mean', content_length),
                'avg_bwd_segment_size': 0,
                'fwd_header_length1': 0,
                'fwd_avg_bytesbulk': 0,
                'fwd_avg_packetsbulk': 0,
                'fwd_avg_bulk_rate': 0,
                'bwd_avg_bytesbulk': 0,
                'bwd_avg_packetsbulk': 0,
                'bwd_avg_bulk_rate': 0,
                'subflow_fwd_packets': network_features.get('total_fwd_packets', 1),
                'subflow_fwd_bytes': network_features.get('total_length_of_fwd_packets', content_length),
                'subflow_bwd_packets': network_features.get('total_backward_packets', 1),
                'subflow_bwd_bytes': network_features.get('total_length_of_bwd_packets', 0),
                'init_win_bytes_forward': 0,
                'init_win_bytes_backward': 0,
                'act_data_pkt_fwd': network_features.get('total_fwd_packets', 1),
                'min_seg_size_forward': 0,
                'active_mean': 0,
                'active_std': 0,
                'active_max': 0,
                'active_min': 0,
                'idle_mean': 0,
                'idle_std': 0,
                'idle_max': 0,
                'idle_min': 0,
                'inbound': 1
            }
            
            # Add the sample to the IP's traffic samples
            traffic_samples_by_ip[ip_address].append(traffic_data)
            
            # Keep only the last 50 samples for this IP
            if len(traffic_samples_by_ip[ip_address]) > 50:
                traffic_samples_by_ip[ip_address].pop(0)
            
            # Analyze traffic if we have 50 samples for this IP
            result, confidence = "Waiting for more data", 0.0
            is_attack = False
            if len(traffic_samples_by_ip[ip_address]) == 50:
                # Convert traffic samples to DataFrame
                traffic_df = pd.DataFrame(traffic_samples_by_ip[ip_address])
                
                # Analyze traffic (aggregate and predict)
                result, confidence = analyze_traffic(traffic_df)
                
                # Determine if it's a potential DDoS attack
                is_attack = "attack" in result.lower()
                
                # Manual threshold for UDP flood (LOIC) and HTTP flood (HOIC) detection
                avg_flow_packetss = traffic_df['flow_packetss'].mean()
                protocol = 6 if traffic_df['total_fwd_packets'].sum() >= traffic_df['total_length_of_bwd_packets'].sum() else 17
                if protocol == 17 and avg_flow_packetss > 100:  # High UDP packet rate
                    result = "LOIC UDP Flood"
                    confidence = 0.95
                    is_attack = True
                elif protocol == 6 and http_request_rate > 50:  # High HTTP request rate
                    result = "HOIC HTTP Flood"
                    confidence = 0.95
                    is_attack = True
        
        # Store analysis result in history
        analysis_history.append({
            'ip_address': ip_address,
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'result': result,
            'confidence': f"{confidence:.2%}",
            'is_attack': is_attack
        })
        
        # Keep only the last 100 entries to avoid memory issues
        if len(analysis_history) > 100:
            analysis_history.pop(0)
        
        return render_template('index.html', 
                            result=result,
                            confidence=f"{confidence:.2%}",
                            is_attack=is_attack,
                            ip_address=ip_address)
    except Exception as e:
        logging.error(f"Error in index route: {e}")
        return render_template('error.html', error=str(e))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', history=analysis_history)

if __name__ == '__main__':
    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
