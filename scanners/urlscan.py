import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("URLSCAN_API_KEY")
BASE = "https://urlscan.io/api/v1"

def scan_url(url: str) -> dict:
    headers = {"API-Key": API_KEY, "Content-Type": "application/json"}
    r = requests.post(f"{BASE}/scan/", headers=headers,
                      json={"url": url, "visibility": "public"})
    if r.status_code != 200:
        return {"error": r.text}
    uuid = r.json()["uuid"]
    time.sleep(15)
    for _ in range(5):
        res = requests.get(f"{BASE}/result/{uuid}/")
        if res.status_code == 200:
            return res.json()
        time.sleep(5)
    return {"error": "Scan timed out"}
