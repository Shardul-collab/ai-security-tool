import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def generate_report(target: str, target_type: str, risk: dict, scan_data: dict) -> dict:
    flags_text = "\n".join(f"- {f}" for f in risk["flags"]) or "- No flags detected"

    prompt = f"""You are a cybersecurity analyst. Generate a professional security assessment report.

Target: {target}
Type: {target_type}
Risk Level: {risk['level']}
Risk Score: {risk['score']}/100
Detected Flags:
{flags_text}

Respond in this exact format:

EXECUTIVE SUMMARY:
[2-3 sentences summarizing the overall security posture]

THREAT ANALYSIS:
[2-3 sentences analyzing specific threats found]

RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]
- [recommendation 3]

VERDICT: {risk['level']}"""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=500
    )
    text = response.choices[0].message.content
    sections = {"executive_summary": "", "threat_analysis": "", "recommendations": [], "verdict": risk["level"]}

    if "EXECUTIVE SUMMARY:" in text:
        sections["executive_summary"] = text.split("EXECUTIVE SUMMARY:")[1].split("THREAT ANALYSIS:")[0].strip()
    if "THREAT ANALYSIS:" in text:
        sections["threat_analysis"] = text.split("THREAT ANALYSIS:")[1].split("RECOMMENDATIONS:")[0].strip()
    if "RECOMMENDATIONS:" in text:
        rec_block = text.split("RECOMMENDATIONS:")[1].split("VERDICT:")[0].strip()
        sections["recommendations"] = [r.lstrip("- ").strip() for r in rec_block.split("\n") if r.strip()]

    return sections
