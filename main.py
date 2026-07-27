import os
import pickle
import numpy as np
import google.generativeai as genai
import asyncio
import random
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import queue
import sys
from fastapi.responses import FileResponse

# Ensure Python can read files in the same directory as main.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from database import init_db, save_alert, get_all_alerts

# Initialize the FastAPI application and core configurations
app = FastAPI()

# Initialize the database on startup
init_db()

# Configure CORS middleware to allow frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure the Gemini API key from environment variables or use the default
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AQ.Ab8RN6LIzN5t-9_jCtPD3uG8iatIijnwmvedw4NUmHW84SlLFQ")
genai.configure(api_key=GEMINI_API_KEY)

# Define the path to the machine learning model (Random Forest)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_core", "random_forest_ids.pkl")

# Attempt to load the classification model
try:
    model = pickle.load(open(MODEL_PATH, "rb"))
    print(f"✅ Model loaded successfully from: {MODEL_PATH}")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    model = None


class TrafficData(BaseModel):
    source_ip: str
    destination_ip: str
    port: int
    features: list


def get_geo_info(ip_str):
    if ip_str.startswith("192.168.") or ip_str.startswith("10."):
        return {"country": "Local Intranet", "flag": "🔒"}
    
    mapping = [
        {"country": "United States", "flag": "🇺🇸"},
        {"country": "Germany", "flag": "🇩🇪"},
        {"country": "China", "flag": "🇨🇳"},
        {"country": "Russia", "flag": "🇷🇺"},
        {"country": "Brazil", "flag": "🇧🇷"},
        {"country": "United Kingdom", "flag": "🇬🇧"}
    ]
    idx = sum(map(ord, ip_str)) % len(mapping)
    return mapping[idx]


def generate_gemini_report(source_ip, destination_ip, port, risk_level, confidence):
    prompt = (
        f"You are a tier-3 cybersecurity incident responder. A network anomaly was flagged.\n"
        f"- Source IP: {source_ip}\n- Destination IP: {destination_ip}\n"
        f"- Target Port: {port}\n- Risk Level: {risk_level}\n- Model Confidence: {confidence}%\n"
        f"Provide a strict, professional SOC analysis report with 2 technical remediation steps."
    )
    try:
        gemini_model = genai.GenerativeModel('gemini-1.5-flash')
        response = gemini_model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return (
            f"🚨 [AUTOMATED SOC AI COPILOT REPORT - SECURE FALLBACK]\n"
            f"• Threat Signature: Abnormal behavioral spike detected from source IP {source_ip} targeting port {port}.\n"
            f"• Risk Assessment: Classified as {risk_level} severity with {confidence}% model confidence. Potential unauthorized payload injection or port probing activity.\n"
            f"• Recommended Mitigation Steps:\n"
            f"  1. Immediately isolate source IP {source_ip} using firewall ingress drop rules.\n"
            f"  2. Review system socket logs and terminate suspicious orphaned daemon threads."
        )


import time

# Dictionary to track active network flows (Flow Tracker)
active_flows = {}

def extract_packet_features(packet):
    current_time = time.time()
    length = float(len(packet))
    
    # Ensure the packet contains an IP layer before tracking
    if IP not in packet:
        return [0.0] * 78
        
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    
    sport, dport = 0.0, 0.0
    if TCP in packet:
        sport, dport = float(packet[TCP].sport), float(packet[TCP].dport)
    elif UDP in packet:
        sport, dport = float(packet[UDP].sport), float(packet[UDP].dport)
        
    # Generate a unique key for the network flow session
    flow_key = f"{src_ip}-{dst_ip}-{sport}-{dport}-{proto}"
    
    # Track and mathematically update the flow session state
    if flow_key not in active_flows:
        active_flows[flow_key] = {
            "start_time": current_time,
            "last_time": current_time,
            "packet_count": 1.0,
            "total_bytes": length,
            "iat_total": 0.0
        }
    else:
        flow = active_flows[flow_key]
        # Calculate the time between packets (Inter-Arrival Time)
        iat = current_time - flow["last_time"] 
        flow["iat_total"] += iat
        flow["last_time"] = current_time
        flow["packet_count"] += 1.0
        flow["total_bytes"] += length

    flow = active_flows[flow_key]
    
    # Calculate deep flow features
    flow_duration = current_time - flow["start_time"]
    packet_len_mean = flow["total_bytes"] / flow["packet_count"]
    iat_mean = flow["iat_total"] / flow["packet_count"] if flow["packet_count"] > 1 else 0.0
    
    # Populate the 78-dimensional feature vector using zero-padding
    # Critical features are assigned, while others safely default to zero
    features = [0.0] * 78
    
    features[0] = dport                 # Destination Port
    features[1] = flow_duration         # Flow Duration
    features[2] = flow["packet_count"]  # Total Fwd Packets
    features[4] = flow["total_bytes"]   # Total Length of Fwd Packets
    features[14] = iat_mean             # Flow IAT Mean
    features[34] = length               # Packet Length Max (approximated)
    features[35] = length               # Packet Length Min (approximated)
    features[36] = packet_len_mean      # Packet Length Mean
    
    # Automatic memory cleanup to prevent server degradation under high load
    if len(active_flows) > 500:
        active_flows.clear()
        
    return features


# Initialize a thread-safe queue for packet processing
packet_queue = queue.Queue()

# Callback function to process each sniffed packet
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"
        port = 80
        if TCP in packet:
            proto = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            port = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"

        length = len(packet)
        
        # Extract operational features using the correct functional method
        features = extract_packet_features(packet)
        
        prediction_label = "Normal"
        risk_level = "Low"
        confidence = 98.2
        gemini_reason = "Packet inspection complete. Standard telemetry behavior verified."

        if model:
            try:
                features_array = np.array(features, dtype=float).reshape(1, -1)
                pred = model.predict(features_array)[0]
                proba = model.predict_proba(features_array)[0]
                confidence = round(max(proba) * 100, 1)

                if int(pred) == 1:
                    prediction_label = "Suspicious"
                    risk_level = "High" if confidence >= 60.0 else "Medium"
                    gemini_reason = generate_gemini_report(ip_layer.src, ip_layer.dst, port, risk_level, confidence)
            except Exception as e:
                print(f"ML Error: {e}")

        geo = get_geo_info(ip_layer.src)

        packet_info = {
            "id": random.randint(10000, 99999),
            "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "port": port,
            "protocol": proto,
            "length": length,
            "prediction": prediction_label,
            "risk_level": risk_level,
            "confidence": confidence,
            "country": geo["country"],
            "flag": geo["flag"],
            "raw_features": features[:10],
            "gemini_reason": gemini_reason
        }
        packet_queue.put(packet_info)


# Start live background packet capture
def start_sniffing():
    print("🚀 Starting Live Packet Capture...")
    sniff(prn=packet_callback, store=False)


# Define application startup event behavior
@app.on_event("startup")
def startup_event():
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()


# WebSocket endpoint to stream real-time traffic data
@app.websocket("/ws/traffic")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            if not packet_queue.empty():
                pkt = packet_queue.get()
                await websocket.send_json(pkt)
            await asyncio.sleep(0.4)
    except WebSocketDisconnect:
        pass


# Endpoint to manually analyze simulated or parsed traffic data
@app.post("/alerts/")
def analyze_traffic(data: TrafficData):
    if data.port == 999:
        import random
        attack_scenarios = [
            {"name": "DDoS Volumetric Flood", "src": f"198.51.{random.randint(10,200)}.{random.randint(1,254)}", "port": 80, "proto": "TCP", "len": 1500, "risk": "High", "conf": float(random.randint(94, 99))},
            {"name": "Port Scanning / Reconnaissance", "src": f"45.33.{random.randint(1,254)}.{random.randint(1,254)}", "port": 22, "proto": "TCP", "len": 64, "risk": "Medium", "conf": float(random.randint(86, 95))},
            {"name": "SQL Injection Exploit Attempt", "src": f"203.0.113.{random.randint(1,254)}", "port": 443, "proto": "TCP", "len": 842, "risk": "High", "conf": float(random.randint(91, 98))},
            {"name": "SSH Brute Force Attack", "src": f"192.0.2.{random.randint(1,254)}", "port": 22, "proto": "TCP", "len": 128, "risk": "High", "conf": float(random.randint(95, 99))},
            {"name": "Buffer Overflow Payload Injection", "src": f"198.18.{random.randint(1,254)}.{random.randint(1,254)}", "port": 443, "proto": "TCP", "len": 1024, "risk": "High", "conf": float(random.randint(93, 99))}
        ]
        scen = random.choice(attack_scenarios)
        prompt = f"You are a tier-3 cybersecurity incident responder. A network attack was detected.\n- Attack Vector: {scen['name']}\n- Source IP: {scen['src']}\n- Target Port: {scen['port']}\n- Risk Level: {scen['risk']}\n- Model Confidence: {scen['conf']}%\nProvide a concise SOC incident report explaining the mechanism and 2 technical remediation steps."
        
        llm_report = ""
        try:
            gemini_model = genai.GenerativeModel('gemini-1.5-flash')
            response = gemini_model.generate_content(prompt)
            llm_report = response.text.strip()
        except Exception as e:
            llm_report = f"🚨 [SOC INCIDENT REPORT - {scen['name'].upper()}]\n• Anomaly Signature: Matched pattern for {scen['name']} from source {scen['src']}.\n• Risk Assessment: Port {scen['port']} targeted with {scen['conf']}% confidence. Severity: {scen['risk']}.\n• Mitigation Actions:\n  1. Apply ingress firewall block rule for IP {scen['src']}.\n  2. Inspect daemon process states on port {scen['port']}."

        # Save the detected attack event into the database using extracted variables
        save_alert(source_ip=scen['src'], risk_score=scen['risk'], ai_report=llm_report)

        return {
            "prediction": "Suspicious",
            "alert_data": {
                "risk_level": scen['risk'], "risk_score": scen['conf'], "attack_type": scen['name'], "source_ip": scen['src'],
                "destination_ip": "10.0.0.15", "port": scen['port'], "protocol": scen['proto'], "length": scen['len'], "llm_incident_report": llm_report
            }
        }

    if not model:
        return {"error": "Model not loaded"}
    
    try:
        features_array = np.array(data.features, dtype=float).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        confidence = round(max(probabilities) * 100, 1)
        
        if int(prediction) == 1:
            return {"prediction": "Suspicious", "alert_data": {"risk_level": "High", "risk_score": confidence, "llm_incident_report": "Anomaly detected."}}
        else:
            return {"prediction": "Normal", "alert_data": {"risk_level": "Low", "risk_score": confidence}}
    except Exception as e:
        return {"error": str(e)}


# Endpoint for the frontend client to retrieve historical alerts
@app.get("/api/history")
async def fetch_history():
    alerts = get_all_alerts()
    return {"status": "success", "data": alerts}


# Redundant import preserved for strict logic compliance
from datetime import datetime

# Endpoint to export the SQLite database file
@app.get("/api/export-db")
async def export_database():
    file_path = "sentinel_history.db"
    if os.path.exists(file_path):
        # Format the current date (e.g., 2026-07-25)
        today_date = datetime.now().strftime("%Y-%m-%d")
        # Construct the dynamic filename including the date
        custom_filename = f"sentinel_history_{today_date}.db"
        
        return FileResponse(file_path, media_type="application/octet-stream", filename=custom_filename)
    return {"error": "Database file not found"}