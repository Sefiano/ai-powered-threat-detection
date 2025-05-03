import pandas as pd
import requests
import time
import numpy as np
import json

# Column mapping to match model's expected features
column_mapping = {
    "Packet Length Std": "Packet_Length_Std",
    "Total Length of Bwd Packets": "Total_Length_of_Bwd_Packets",
    "Subflow Bwd Bytes": "Subflow_Bwd_Bytes",
    "Destination Port": "Destination_Port",
    "Packet Length Variance": "Packet_Length_Variance",
    "Bwd Packet Length Mean": "Bwd_Packet_Length_Mean",
    "Avg Bwd Segment Size": "Avg_Bwd_Segment_Size",
    "Bwd Packet Length Max": "Bwd_Packet_Length_Max",
    "Init_Win_bytes_backward": "Init_Win_bytes_backward",
    "Total Length of Fwd Packets": "Total_Length_of_Fwd_Packets",
    "Subflow Fwd Bytes": "Subflow_Fwd_Bytes",
    "Init_Win_bytes_forward": "Init_Win_bytes_forward",
    "Average Packet Size": "Average_Packet_Size",
    "Packet Length Mean": "Packet_Length_Mean",
    "Max Packet Length": "Max_Packet_Length",
    "Fwd Packet Length Max": "Fwd_Packet_Length_Max"
}

# Load the synthetic dataset
csv_file_path = r"C:\Users\User\Desktop\nokood\project\sampled_dataset.csv"
data_df = pd.read_csv(csv_file_path)

# Clean column names
data_df.columns = data_df.columns.str.strip()

# Replace NaN and infinite values
data_df.replace([np.inf, -np.inf], np.nan, inplace=True)
data_df.fillna(0, inplace=True)

# API endpoint
api_url = "http://127.0.0.1:8000/predict"

# Log file path
log_file = "logs.txt"

# Send requests one by one
for index, row in data_df.iterrows():
    payload = {api_key: float(row[csv_col]) for csv_col, api_key in column_mapping.items()}
    try:
        response = requests.post(api_url, json=payload)
        result = response.json()

        event_log = f"[EVENT] {json.dumps(result)}"
        
        # Print to terminal (for debugging)
        print(event_log)

        # Write to log file
        with open(log_file, "a") as log:
            log.write(event_log + "\n")

    except Exception as e:
        error_log = f"[ERROR] on row {index}: {e}"
        print(error_log)
        with open(log_file, "a") as log:
            log.write(error_log + "\n")

    time.sleep(1)  # Small delay between requests
