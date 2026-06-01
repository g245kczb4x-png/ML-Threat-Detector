# SecureBERT Active Defense SIEM

A real-time cybersecurity honeypot and SIEM dashboard that uses SecureBERT for command classification, BERT semantic fingerprinting, and DBSCAN clustering to detect, classify, and automatically terminate malicious attacker sessions.

---

## Project Overview

Unlike traditional signature-based detection (which looks for exact matches), this system analyzes the intent of shell commands. It can see through attacker obfuscation—like extra whitespace, shell wrappers, and Base64 encoding—to identify threats with high mathematical confidence.

---

## Core Features

### Intelligent Classification
Maps commands to MITRE ATT&CK tactics such as:
- Credential Access
- Reconnaissance
- Persistence
- Execution
- Discovery

### Active Defense (Kill Signal)
Automatically terminates a socket connection if the ML model identifies a critical threat with **>85% confidence**.

### Real-time SIEM Dashboard
A modern Next.js frontend that streams telemetry and attack events through WebSockets.

### Adversarial Hardening
A preprocessing pipeline that normalizes noisy or obfuscated attacker commands using:
- Whitespace stripping
- Command normalization
- Shell wrapper removal
- Base64 de-obfuscation

---

## Tech Stack

| Component | Technology |
|---|---|
| Machine Learning | Python, Scikit-Learn (TF-IDF, Logistic Regression) |
| Backend / API | FastAPI, WebSockets |
| Frontend | Next.js 14, Tailwind CSS, Lucide-React |
| Agent / Probe | Python Socket Programming |

---

## How the ML Engine Works

The engine uses a **TF-IDF Vectorizer** with an **N-gram range of (2, 5)**.

This allows the model to analyze small fragments of characters rather than relying only on full words, making it highly resilient against command obfuscation techniques.

### Example

Even if an attacker runs:

```bash
/bin/sh -c "cat /etc/shadow"
```

The model still recognizes character sequences like:

```text
/etc/sha
```

as high-weight indicators for:

```text
CREDENTIAL_ACCESS
```

regardless of surrounding shell wrappers or formatting tricks.

---

## Getting Started

### 1️The SIEM Backend

```bash
cd siem
pip install -r requirements.txt
export PYTHONPATH=$PYTHONPATH:.
uvicorn main:app --reload
```

---

### 2️The Honeypot Agent

```bash
cd agent
python3 listener.py
```

---

### 3️The Dashboard

```bash
cd dashboard
npm install
npm run dev
```

---

## Suggested Project Structure

```text
project-root/
│
├── agent/
│   └── listener.py
│
├── dashboard/
│   ├── app/
│   └── components/
│
├── siem/
│   ├── main.py
│   ├── model/
│   └── preprocessing/
│
├── requirements.txt
└── README.md
```

---

## Example Detection Flow

1. Attacker connects to honeypot socket
2. Command is captured in real time
3. NLP preprocessing pipeline normalizes input
4. TF-IDF vectorizer transforms command into features
5. Logistic Regression classifier predicts ATT&CK tactic
6. High-confidence malicious sessions are terminated
7. Event is streamed to the SIEM dashboard instantly

---

## MITRE ATT&CK Integration

The system classifies attacker behavior into MITRE ATT&CK-aligned categories including:

- Credential Access
- Discovery
- Reconnaissance
- Privilege Escalation
- Persistence
- Command and Scripting Interpreter

---

## Future Improvements

- Deep Learning-based detection models
- Threat intelligence integration
- GeoIP attacker tracking
- Dockerized deployment
- Authentication and RBAC
- Historical analytics and reporting
- Live packet inspection support

---

## Disclaimer

This project is for educational and research purposes only. It is designed to demonstrate Machine Learning applications in cybersecurity.

Do **not** deploy this agent on production systems without proper security hardening.
