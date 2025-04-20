from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model
import joblib
import logging
from datetime import datetime
import time
from collections import defaultdict

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load model and preprocessors
try:
    model = load_model('model.keras')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
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
    'http_request_rate'
]

DROP_COLS = [
    'unnamed_0', 'flow_id', 'source_ip', 'destination_ip',
    'source_port', 'destination_port', 'timestamp', 'protocol'
]

# Store request timestamps for rate limiting and analysis
request_log = defaultdict(list)
# Store analysis history for dashboard
analysis_history = []

# Get the feature names that the scaler was trained on
# This assumes the scaler was fitted with a DataFrame and we can access its feature names
try:
    scaler_feature_names = scaler.feature_names_in_ if hasattr(scaler, 'feature_names_in_') else None
except Exception as e:
    logging.warning(f"Could not retrieve scaler feature names: {e}")
    scaler_feature_names = None

def preprocess_data(data):
    """Preprocess input data for model prediction"""
    try:
        # Convert to DataFrame
        df = pd.DataFrame([data])
        
        # Ensure all required features are present
        for feature in FEATURES:
            if feature not in df.columns and feature not in DROP_COLS:
                df[feature] = 0
        
        # Drop unnecessary columns
        df = df.drop(columns=[col for col in DROP_COLS if col in df.columns], errors='ignore')
        
        # If scaler feature names are available, drop features not seen during fit
        if scaler_feature_names is not None:
            unseen_features = [col for col in df.columns if col not in scaler_feature_names]
            df = df.drop(columns=unseen_features, errors='ignore')
            logging.info(f"Dropped unseen features: {unseen_features}")
        
        # Add missing features that the scaler expects
        if scaler_feature_names is not None:
            for feature in scaler_feature_names:
                if feature not in df.columns:
                    df[feature] = 0
        
        # Scale numerical features
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns
        if numerical_cols.empty:
            raise ValueError("No numerical columns to scale.")
        
        df[numerical_cols] = scaler.transform(df[numerical_cols])
        
        return df
    except Exception as e:
        logging.error(f"Error in preprocessing: {e}")
        raise

def analyze_traffic(data):
    """Analyze traffic data using the loaded model"""
    try:
        # Preprocess data
        processed_data = preprocess_data(data)
        
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
    request_log[ip_address].append(current_time)
    
    # Keep only requests from the last 60 seconds
    request_log[ip_address] = [t for t in request_log[ip_address] if current_time - t < 60]
    
    # Calculate requests per second
    return len(request_log[ip_address]) / 60.0

@app.route('/')
def index():
    try:
        ip_address = request.remote_addr
        current_time = datetime.now()
        
        # Calculate request rate for HTTP flood detection
        http_request_rate = calculate_request_rate(ip_address)
        
        # Collect traffic data from HTTP request
        content_length = int(request.headers.get('Content-Length', 0))
        user_agent = request.headers.get('User-Agent', '')
        
        traffic_data = {
            'source_ip': ip_address,
            'destination_ip': request.host.split(':')[0],
            'source_port': 0,  # Not available in HTTP context
            'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
            'protocol': 6,  # TCP for HTTP
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'flow_duration': 1000,  # Placeholder
            'total_fwd_packets': 1,  # Single HTTP request
            'total_backward_packets': 1,  # Single HTTP response (assumed)
            'total_length_of_fwd_packets': content_length,
            'total_length_of_bwd_packets': 0,
            'fwd_packet_length_max': content_length,
            'fwd_packet_length_min': content_length,
            'fwd_packet_length_mean': content_length,
            'fwd_packet_length_std': 0,
            'bwd_packet_length_max': 0,
            'bwd_packet_length_min': 0,
            'bwd_packet_length_mean': 0,
            'bwd_packet_length_std': 0,
            'http_request_rate': http_request_rate,
            'simillarhttp': 1 if 'http' in user_agent.lower() else 0,
            'inbound': 1,
            'flow_bytess': 0,
            'flow_packetss': 0,
            'flow_iat_mean': 0,
            'flow_iat_std': 0,
            'flow_iat_max': 0,
            'flow_iat_min': 0,
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
            'fwd_packetss': 0,
            'bwd_packetss': 0,
            'min_packet_length': content_length,
            'max_packet_length': content_length,
            'packet_length_mean': content_length,
            'packet_length_std': 0,
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
            'average_packet_size': content_length,
            'avg_fwd_segment_size': content_length,
            'avg_bwd_segment_size': 0,
            'fwd_header_length1': 0,
            'fwd_avg_bytesbulk': 0,
            'fwd_avg_packetsbulk': 0,
            'fwd_avg_bulk_rate': 0,
            'bwd_avg_bytesbulk': 0,
            'bwd_avg_packetsbulk': 0,
            'bwd_avg_bulk_rate': 0,
            'subflow_fwd_packets': 1,
            'subflow_fwd_bytes': content_length,
            'subflow_bwd_packets': 1,
            'subflow_bwd_bytes': 0,
            'init_win_bytes_forward': 0,
            'init_win_bytes_backward': 0,
            'act_data_pkt_fwd': 1,
            'min_seg_size_forward': 0,
            'active_mean': 0,
            'active_std': 0,
            'active_max': 0,
            'active_min': 0,
            'idle_mean': 0,
            'idle_std': 0,
            'idle_max': 0,
            'idle_min': 0,
            'unique_source_ips': 1,
            'packet_rate': http_request_rate
        }
        
        # Analyze traffic
        result, confidence = analyze_traffic(traffic_data)
        
        # Determine if it's a potential DDoS attack
        is_attack = result.lower() in ['attack', 'ddos', 'loic', 'hoic']
        
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
    app.run(host='0.0.0.0', port=5000, debug=True)
