# 🛡️ AI-Powered Security Assessment Tool

Built for AnantNetra Technologies AI Engineer Intern Assignment.

## Overview
A security assessment tool that analyzes URLs, IP addresses, and files using multiple threat intelligence APIs and generates AI-powered security reports.

## Architecture
## Setup

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/ai-security-tool.git
cd ai-security-tool
```

### 2. Create virtual environment
```bash
python3 -m venv venv && source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Add API keys
```bash
cp .env.example .env
nano .env
```

### 5. Run the app
```bash
streamlit run ui/app.py
```

## API Keys Required
| Service | URL | Free Tier |
|---|---|---|
| VirusTotal | https://virustotal.com | 500 req/day |
| AbuseIPDB | https://abuseipdb.com | 1000 req/day |
| URLScan | https://urlscan.io | 60 req/hour |
| Groq | https://console.groq.com/home | various models avilable |

## Risk Scoring
| Condition | Score |
|---|---|
| Malware Detection | +40 |
| Phishing Detection | +30 |
| Malicious Domain | +20 |
| Suspicious Reputation | +10 |

**Levels:** Safe · Low Risk · Medium Risk · High Risk · Critical

## Architecture
See [architecture.md](architecture.md)
