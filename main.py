from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
import shap
import uuid
import os

# Helper function to print and log messages
def log_print(msg):
    print(msg)
    with open("server_logs.txt", "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# List of expected feature names (order matters)
FEATURES = [
    "Packet Length Std", "Total Length of Bwd Packets",
    "Subflow Bwd Bytes", "Destination Port",
    "Packet Length Variance", "Bwd Packet Length Mean",
    "Avg Bwd Segment Size", "Bwd Packet Length Max",
    "Init_Win_bytes_backward", "Total Length of Fwd Packets",
    "Subflow Fwd Bytes", "Init_Win_bytes_forward",
    "Average Packet Size", "Packet Length Mean", "Max Packet Length",
    "Fwd Packet Length Max"
]

class ThreatData(BaseModel):
    Packet_Length_Std: float
    Total_Length_of_Bwd_Packets: float
    Subflow_Bwd_Bytes: float
    Destination_Port: float
    Packet_Length_Variance: float
    Bwd_Packet_Length_Mean: float
    Avg_Bwd_Segment_Size: float
    Bwd_Packet_Length_Max: float
    Init_Win_bytes_backward: float
    Total_Length_of_Fwd_Packets: float
    Subflow_Fwd_Bytes: float
    Init_Win_bytes_forward: float
    Average_Packet_Size: float
    Packet_Length_Mean: float
    Max_Packet_Length: float
    Fwd_Packet_Length_Max: float

    def to_dataframe(self):
        data = {
            "Packet Length Std": self.Packet_Length_Std,
            "Total Length of Bwd Packets": self.Total_Length_of_Bwd_Packets,
            "Subflow Bwd Bytes": self.Subflow_Bwd_Bytes,
            "Destination Port": self.Destination_Port,
            "Packet Length Variance": self.Packet_Length_Variance,
            "Bwd Packet Length Mean": self.Bwd_Packet_Length_Mean,
            "Avg Bwd Segment Size": self.Avg_Bwd_Segment_Size,
            "Bwd Packet Length Max": self.Bwd_Packet_Length_Max,
            "Init_Win_bytes_backward": self.Init_Win_bytes_backward,
            "Total Length of Fwd Packets": self.Total_Length_of_Fwd_Packets,
            "Subflow Fwd Bytes": self.Subflow_Fwd_Bytes,
            "Init_Win_bytes_forward": self.Init_Win_bytes_forward,
            "Average Packet Size": self.Average_Packet_Size,
            "Packet Length Mean": self.Packet_Length_Mean,
            "Max Packet Length": self.Max_Packet_Length,
            "Fwd Packet Length Max": self.Fwd_Packet_Length_Max
        }
        return pd.DataFrame([data], columns=FEATURES)

app = FastAPI(title="AI-Powered Fintech Threat Detection API")

MODEL_PATH = "C:\\Users\\User\\Desktop\\nokood\\project\\threat.pkl"
try:
    rf_model = joblib.load(MODEL_PATH)
    log_print("Model loaded successfully.")
except Exception as e:
    log_print(f"Error loading model: {e}")
    raise HTTPException(status_code=500, detail=f"Error loading model: {e}")

explainer = shap.TreeExplainer(rf_model)
shap_storage = {}

@app.get("/")
def read_root():
    log_print("Received GET / request.")
    return {"message": "Welcome to the AI-Powered Fintech Threat Detection API."}

@app.post("/predict")
def predict_threat(data: ThreatData):
    df = data.to_dataframe()
    request_id = str(uuid.uuid4())

    # Make prediction
    try:
        prediction = rf_model.predict(df)[0]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {e}")

    threat_label = "Malicious" if prediction == 1 else "Benign"

    # Compute SHAP values and store them along with threat_level
    try:
        raw_shap = explainer.shap_values(df)
        if isinstance(raw_shap, np.ndarray) and len(raw_shap.shape) == 3:
            shap_array = raw_shap[0, :, 1]
        elif isinstance(raw_shap, list):
            shap_array = raw_shap[1] if len(raw_shap) > 1 and raw_shap[1].size > 0 else raw_shap[0]
        elif isinstance(raw_shap, np.ndarray):
            shap_array = raw_shap
        else:
            shap_array = None

        if shap_array is not None and shap_array.size > 0:
            shap_dict = {FEATURES[i]: float(shap_array[i]) for i in range(len(FEATURES))}
        else:
            shap_dict = {}
        # <-- Added threat_level here -->
        shap_storage[request_id] = {"id": request_id, "shap_values": shap_dict, "threat_level": threat_label}
    except Exception as e:
        shap_storage[request_id] = {"id": request_id, "shap_values": {}, "threat_level": threat_label}

    print(f"[PREDICT] => threat_level: {threat_label}, id: {request_id}")
    return {"threat_level": threat_label, "id": request_id}

@app.get("/explain/{request_id}")
def get_shap_values(request_id: str):
    if request_id not in shap_storage:
        log_print(f"[ERROR] Request ID {request_id} not found.")
        raise HTTPException(status_code=404, detail="Request ID not found")
    log_print(f"SHAP values retrieved for {request_id}.")
    return shap_storage[request_id]

@app.get("/debug/shap_storage")
def debug_shap_storage():
    return shap_storage

@app.get("/generate_report/{request_id}")
def generate_report(request_id: str):
    if request_id not in shap_storage:
        raise HTTPException(status_code=404, detail="Request ID not found")
    
    event_data = shap_storage[request_id]
    shap_values = event_data["shap_values"]
    if not shap_values:
        raise HTTPException(status_code=400, detail="No SHAP values available for this request")
    
    # Build an improved prompt:
    prompt = "### Network Threat Analysis Report\n\n"
    prompt += "Based on the following SHAP values, determine the most likely type of attack from the options below, explain its impact, and provide mitigation recommendations.\n\n"
    prompt += "Options: DDoS, DoS Hulk, GoldenEye, Slowloris, Slowhttptest, PortScan, Heartbleed\n\n"
    prompt += "SHAP Values:\n"
    for feature, value in shap_values.items():
        prompt += f"- **{feature}**: {value:.2f}\n"
    prompt += "\nAnswer by specifying the attack type, explaining its impact, and providing actionable mitigation recommendations."

    # Define the LLM API URL (using the same logic as your test script)
    ollama_api_url = "http://localhost:11434/api/generate"
    payload = {
        "model": "deepseek-r1:1.5b",
        "prompt": prompt,
        "stream": False
    }

    import requests
    try:
        # Simulate the processing delay as in your test script
        log_print("Processing report generation (waiting 2 seconds)...")
        import time
        time.sleep(2)
        # Send request to LLM
        response = requests.post(ollama_api_url, json=payload, timeout=30)
        for _ in range(5):
            log_print(".")
            time.sleep(1)
        if response.status_code == 200:
            raw_report = response.json().get("response", "Error generating report.")
        else:
            raw_report = f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        raw_report = f"Failed to connect to DeepSeek: {str(e)}"

    # Clean the report by removing <think> sections
    import re
    def clean_response(response_text):
        cleaned_text = re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL)
        return cleaned_text.strip()

    report = clean_response(raw_report)
    log_print(f"Report generated for {request_id}.")
    return {"event_id": request_id, "report": report}
