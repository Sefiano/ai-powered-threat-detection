import pandas as pd

# Paths to datasets
file_paths = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Wednesday-WorkingHours.pcap_ISCX.csv",  # Includes DoS & Heartbleed
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
]

# Load datasets
dfs = [pd.read_csv(file) for file in file_paths]

# Merge datasets
df_combined = pd.concat(dfs, ignore_index=True)

# Standardize column names (strip spaces)
df_combined.columns = df_combined.columns.str.strip()

# Convert labels into binary (Malicious = 1, Benign = 0)
df_combined["Label"] = df_combined["Label"].apply(lambda x: 1 if x != "BENIGN" else 0)

# Select features based on Information Gain
selected_features = [
    "Packet Length Std", "Total Length of Bwd Packets",
    "Subflow Bwd Bytes", "Destination Port",
    "Packet Length Variance", "Bwd Packet Length Mean",
    "Avg Bwd Segment Size", "Bwd Packet Length Max",
    "Init_Win_bytes_backward", "Total Length of Fwd Packets",
    "Subflow Fwd Bytes", "Init_Win_bytes_forward",
    "Average Packet Size", "Packet Length Mean", "Max Packet Length",
    "Fwd Packet Length Max"
]

df_combined = df_combined[selected_features + ["Label"]]

# Save the processed dataset
output_path = "merged_dataset.csv"
df_combined.to_csv(output_path, index=False)

print(f"✅ Merged dataset saved at {output_path}")
