# 🛡️ Sentinel-IDS
> An advanced, enterprise-grade Network Intrusion Detection System (NIDS) engineered for real-time threat intelligence and automated security operations.

---

## 🚀 Key Features

* **Real-Time Network Telemetry:** Powered by a high-performance **FastAPI** backend and **Scapy**, the system captures live network packets passively to monitor traffic patterns continuously.
* **Machine Learning Threat Detection:** Integrates a trained **Random Forest** classifier to evaluate streaming packet features and instantly flag network anomalies and potential intrusions.
* **Automated AI Incident Response:** Leverages **Google Gemini** to dynamically generate professional Security Operations Center (SOC) incident reports complete with precise technical remediation steps.
* **Interactive Operations Dashboard:** Built using **React** and **Tailwind CSS** with **WebSocket** integration, providing seamless, real-time data streaming for security analysts.
* **Incident Logging and Management:** Features complete **SQLite** database integration to securely store historical security alerts and allow direct database exporting from the interface.

---

## 🏗️ Architecture & Tech Stack

```text
[ Live Network Traffic ] 
       │ (Scapy Packet Capture)
       ▼
[ FastAPI Backend ] ──(WebSocket)──> [ React & Tailwind Dashboard ]
       │
       ├──> [ Random Forest ML Model ] (Anomaly Detection)
       └──> [ Google Gemini API ] (Automated SOC Incident Reports)
       │
       ▼
[ SQLite Database ] (Persistent Storage & Export)
