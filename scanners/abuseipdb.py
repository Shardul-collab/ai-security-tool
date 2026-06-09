import requests
import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE = "https://api.abuseipdb.com/api/v2"

def check_ip(ip: str) -> dict:
    r = requests.get(f"{BASE}/check",
                     headers={"Key": API_KEY, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True})
    return r.json()
