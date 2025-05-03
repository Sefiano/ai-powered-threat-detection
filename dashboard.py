import streamlit as st
import os
import time
import requests
import json
import re
import pyperclip


PROJECT_PATH = r"C:\Users\User\Desktop\nokood\project"
LOG_FILE = os.path.join(PROJECT_PATH, "logs.txt")

# Helper function to extract ID from log entry
def extract_id_from_log(log_entry):
    match = re.search(r'"id":\s*"([^"]+)"', log_entry)
    return match.group(1) if match else None

# Helper function to remove <think> ... </think> from LLM responses
def clean_response(response_text):
    cleaned_text = re.sub(r"<think>.*?</think>", "", response_text, flags=re.DOTALL)
    return cleaned_text.strip()

def check_server_running():
    """Check if FastAPI server is up by sending an HTTP GET to /."""
    try:
        resp = requests.get("http://127.0.0.1:8000/", timeout=2)
        return (resp.status_code == 200)
    except:
        return False

def read_logs():
    """Read the latest logs from logs.txt."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as log:
            return log.readlines()
    return []

# Custom CSS for better button alignment
st.markdown("""
<style>
    .stButton > button {
        padding: 0.5rem 1rem;
        height: auto;
        width: auto;
        white-space: nowrap;
    }
    div[data-testid="column"] {
        display: flex;
        justify-content: flex-end;
        align-items: center;
        padding: 0;
    }
</style>
""", unsafe_allow_html=True)

st.title("AI-Powered Threat Detection Dashboard")

# Create three tabs
tab_control, tab_logs, tab_report = st.tabs(["Control", "Logs", "Generate Report"])

# ------------------------------------------------------------------
# CONTROL TAB
# ------------------------------------------------------------------
with tab_control:
    st.header("Control Panel")

    # Server Controls
    st.subheader("Server Controls")

    if st.button("Start Server"):
        os.system(f'cd "{PROJECT_PATH}" && env\\Scripts\\activate && start cmd /k "uvicorn main:app --host 127.0.0.1 --port 8000 --reload"')
        st.success("Server started in a new terminal window.")

    if st.button("Check Server Status"):
        if check_server_running():
            st.success("Server is Running!")
        else:
            st.error("Server is not responding.")

    # Prediction Script Controls
    st.subheader("Prediction Script Controls")
    if st.button("Run Prediction Script"):
        os.system(f'cd "{PROJECT_PATH}" && env\\Scripts\\activate && start cmd /k "python script.py"')
        st.success("Prediction script started in a new terminal window.")

# ------------------------------------------------------------------
# LOGS TAB
# ------------------------------------------------------------------
with tab_logs:
    st.header("Logs")
    
    # Store logs in session state to prevent refresh on button click
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    
    if st.button("Refresh Logs"):
        st.session_state.logs = read_logs()
    
    # Display logs from session state
    for idx, log_entry in enumerate(st.session_state.logs[-10:]):
        log_id = extract_id_from_log(log_entry)
        if log_id:
            col1, col2 = st.columns([0.92, 0.08])
            with col1:
                st.text(log_entry.strip())
            with col2:
                if st.button("📋", key=f"copy_{idx}", help="Copy ID"):
                    pyperclip.copy(log_id)
                    st.session_state.event_id = log_id
                    st.toast(f"✅ ID copied!")
        else:
            st.text(log_entry.strip())
    
    if not st.session_state.logs:
        st.write("Click 'Refresh Logs' to load the latest logs.")

# ------------------------------------------------------------------
# GENERATE REPORT TAB
# ------------------------------------------------------------------
with tab_report:
    st.header("Generate Report")

    # Use session state to store the copied event ID
    if 'event_id' not in st.session_state:
        st.session_state.event_id = ""
    
    event_id = st.text_input("Enter Event ID (from logs)", value=st.session_state.event_id)

    if st.button("Generate Report"):
        if not event_id:
            st.error("Please enter a valid Event ID.")
            st.stop()

        # 1. Fetch SHAP values and threat level from the server
        shap_url = f"http://127.0.0.1:8000/explain/{event_id}"
        try:
            shap_response = requests.get(shap_url, timeout=5)
        except Exception as e:
            st.error(f"Failed to connect to server: {e}")
            st.stop()

        if shap_response.status_code != 200:
            st.error(f"Invalid Event ID or server error: {shap_response.text}")
            st.stop()

        event_data = shap_response.json()
        shap_values = event_data.get("shap_values", {})
        threat_level = event_data.get("threat_level", "Unknown")

        if not shap_values:
            st.error("No SHAP values found for this Event ID.")
            st.stop()

        # 2. Build a prompt
        prompt = "### Network Threat Analysis Report\n\n"
        if threat_level == "Benign":
            prompt += (
                "Based on the following SHAP values, analyze why this event was classified as benign. "
                "Explain the factors that contributed to a benign classification and provide recommendations for maintaining network security.\n\n"
            )
        else:
            prompt += (
                "Based on the following SHAP values, determine the most likely type of attack from the options below, "
                "explain its impact, and provide actionable mitigation recommendations.\n\n"
                "Options: DDoS, DoS Hulk, GoldenEye, Slowloris, Slowhttptest, PortScan, Heartbleed\n\n"
            )
        prompt += "SHAP Values:\n"
        for feature, value in shap_values.items():
            prompt += f"- **{feature}**: {value:.2f}\n"
        if threat_level == "Benign":
            prompt += (
                "\nAnswer by explaining the key factors leading to a benign classification and suggest ways to maintain or enhance security."
            )
        else:
            prompt += (
                "\nAnswer by specifying the attack type, explaining its impact, and providing actionable mitigation recommendations."
            )

        # 3. Use a spinner while contacting the LLM
        with st.spinner("Processing... This may take a few seconds."):
            time.sleep(2)  # Simulate a short delay

            # 4. Send request to the LLM
            ollama_api_url = "http://localhost:11434/api/generate"
            payload = {"model": "deepseek-r1:1.5b", "prompt": prompt, "stream": False}
            try:
                response = requests.post(ollama_api_url, json=payload, timeout=200)
                response.raise_for_status()
                raw_report = response.json().get("response", "No response received.")
                report_text = clean_response(raw_report)
            except Exception as e:
                st.error(f"Error communicating with LLM: {e}")
                st.stop()

        # 5. Once the spinner is done, show success and the report
        st.success("Report generated successfully! See below.")
        st.subheader("Generated Report")
        st.write(report_text)
