# AI-Powered Threat Detection Dashboard

This project is a prototype system for detecting and reporting threats in a simulated fintech network environment. It leverages machine learning for classification, SHAP for explainability, and a locally hosted LLM to generate automated forensic reports based on detected anomalies. The system is designed for extensibility and future integration into production-level SOC workflows.

---

## 🔍 Project Description

The dashboard enables users to:
- Launch a server and interact with a clean UI.
- Upload or parse logs to detect malicious activity (binary classification: Benign vs Malicious).
- Automatically generate a detailed threat report if a suspicious log is detected.
- Explain model decisions using SHAP values and summarize the reasoning using an LLM.

The system was developed as part of a final-year cybersecurity project focused on combining explainable AI with practical threat analysis and reporting.

---

## ⚙️ Features

- 🧠 **ML-Based Threat Detection** using a Random Forest model
- 🔎 **Explainable AI (SHAP)** integration for feature importance
- 📝 **Automated Forensic Report Generation** via a local GPT-based model
- 💻 **Web Dashboard** built with Streamlit
- 📁 **Command-Line and GUI Support**
- 🔐 **Local-only Deployment** for secure experimentation

---

## 🚀 Demo Videos

Watch the full workflow of the system prototype:

1. **Running the Dashboard from Command Line**  
   https://drive.google.com/file/d/15KXxfwi9QEuvuLVC4hqTHgVP2QBfRYiO/view

2. **Operating the Dashboard Interface**  
   https://drive.google.com/file/d/16RgaBAypTQyGoiEO6MS7FXVAImqAz0v3/view

3. **Generating the Report from Selected Log ID**  
   https://drive.google.com/file/d/1jNMJVdY0W4LnHQPYQEmBNRfsRC4vCdiT/view

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10+
- `pip` package manager
- Virtual environment (recommended)

### Clone & Setup
```bash
git clone https://github.com/yourusername/ai-threat-detection-dashboard.git
cd ai-threat-detection-dashboard
python -m venv env
source env/bin/activate  # or env\Scripts\activate on Windows
pip install -r requirements.txt



uvicorn main:app --host 127.0.0.1 --port 8000 --reload
streamlit run dashboard.py
