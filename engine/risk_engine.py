def calculate_risk(vt_result: dict = None, abuse_result: dict = None, urlscan_result: dict = None) -> dict:
    score = 0
    flags = []

    # VirusTotal parsing
    if vt_result and "data" in vt_result:
        stats = {}
        try:
            attrs = vt_result["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", attrs.get("stats", {}))
        except:
            pass

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 5:
            score += 40
            flags.append(f"Malware detected by {malicious} engines")
        if malicious >= 2:
            score += 30
            flags.append("Phishing indicators found")
        if malicious >= 1:
            score += 20
            flags.append("Flagged as malicious domain")
        if suspicious >= 1:
            score += 10
            flags.append(f"Suspicious by {suspicious} engines")

    # AbuseIPDB parsing
    if abuse_result and "data" in abuse_result:
        data = abuse_result["data"]
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        if abuse_score >= 80:
            score += 40
            flags.append(f"High abuse confidence: {abuse_score}%")
        elif abuse_score >= 40:
            score += 20
            flags.append(f"Moderate abuse confidence: {abuse_score}%")
        elif abuse_score >= 10:
            score += 10
            flags.append(f"Low abuse reports: {total_reports} reports")

    # URLScan parsing
    if urlscan_result and "verdicts" in urlscan_result:
        verdicts = urlscan_result["verdicts"].get("overall", {})
        if verdicts.get("malicious"):
            score += 40
            flags.append("URLScan flagged as malicious")
        if verdicts.get("score", 0) > 50:
            score += 20
            flags.append(f"URLScan risk score: {verdicts.get('score')}")

    return {
        "score": min(score, 100),
        "flags": flags,
        "level": get_risk_level(score)
    }

def get_risk_level(score: int) -> str:
    if score == 0:
        return "Safe"
    elif score <= 20:
        return "Low Risk"
    elif score <= 40:
        return "Medium Risk"
    elif score <= 70:
        return "High Risk"
    else:
        return "Critical"
