import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Load merged dataset
file_path = "merged_dataset.csv"
df = pd.read_csv(file_path)

# Define selected features
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

# Select only the required features
df = df[selected_features + ["Label"]]

# Handle missing values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.mean(), inplace=True)

# Split into features (X) and target (y)
X = df.drop(columns=["Label"])
y = df["Label"]

# Split into training & test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train the Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# Make predictions
y_pred = rf_model.predict(X_test)

# Evaluate model
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:\n", classification_report(y_test, y_pred))


# Save trained model

joblib.dump(rf_model, "threat.pkl")