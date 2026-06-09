import requests
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY}

def scan_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = requests.get(f"{BASE}/urls/{url_id}", headers=HEADERS)
    if r.status_code == 404:
        # Submit first
        r = requests.post(f"{BASE}/urls", headers=HEADERS, data={"url": url})
        url_id = r.json()["data"]["id"]
        r = requests.get(f"{BASE}/analyses/{url_id}", headers=HEADERS)
    return r.json()

def scan_ip(ip: str) -> dict:
    r = requests.get(f"{BASE}/ip_addresses/{ip}", headers=HEADERS)
    return r.json()

def scan_file(file_bytes: bytes, filename: str) -> dict:
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    # Check if already analyzed
    r = requests.get(f"{BASE}/files/{file_hash}", headers=HEADERS)
    if r.status_code == 200:
        return r.json()
    # Upload file
    r = requests.post(f"{BASE}/files", headers=HEADERS,
                      files={"file": (filename, file_bytes)})
    analysis_id = r.json()["data"]["id"]
    r = requests.get(f"{BASE}/analyses/{analysis_id}", headers=HEADERS)
    return r.json()
