# Sentinel-IDS // AI-Powered Security Operations Center (SOC)

An advanced, real-time Network Intrusion Detection System (NIDS) integrated with a Machine Learning classification pipeline and an automated AI incident analysis engine powered by Google Gemini.

---

## Key Features

* **Real-Time Packet Capture:** Passive network sniffing using Scapy to monitor traffic packets live.
* **ML Threat Detection:** Uses a trained Random Forest Classifier to evaluate packet features and instantly flag anomalies.
* **AI Incident Analysis:** Automatically generates professional SOC incident reports and technical remediation steps for suspicious packets using Gemini.
* **Interactive Dashboard:** Built with React, Tailwind CSS, and WebSockets for seamless real-time telemetry streaming.
* **Database & Exporting:** SQLite integration to log historical incidents and export database files directly from the UI.

---

## Tech Stack

* **Backend:** FastAPI, Python, WebSockets, Scapy, Scikit-Learn
* **Frontend:** React, Tailwind CSS, Lucide Icons
* **AI Engine:** Google Gemini API

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_USERNAME/sentinel-ids.git](https://github.com/YOUR_USERNAME/sentinel-ids.git)
cd sentinel-ids
