import os
from dotenv import load_dotenv

load_dotenv()

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

    text = None

    # Try Groq first
    try:
        from groq import Groq
        client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )
        text = response.choices[0].message.content
        print("[AI] Using Groq")
    except Exception as e:
        print(f"[AI] Groq failed: {e}")

    # Fallback to Gemini
    if not text:
        try:
            import google.generativeai as genai
            genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
            model = genai.GenerativeModel("gemini-2.0-flash")
            response = model.generate_content(prompt)
            text = response.text
            print("[AI] Using Gemini")
        except Exception as e:
            print(f"[AI] Gemini failed: {e}")

    # Static fallback
    if not text:
        print("[AI] Using static fallback")
        return {
            "executive_summary": f"The target {target} has been assessed with a risk score of {risk['score']}/100.",
            "threat_analysis": f"Analysis detected: {', '.join(risk['flags']) or 'no major threats'}.",
            "recommendations": ["Monitor the target regularly.", "Keep security tools updated.", "Review flagged indicators manually."],
            "verdict": risk["level"]
        }

    sections = {"executive_summary": "", "threat_analysis": "", "recommendations": [], "verdict": risk["level"]}
    if "EXECUTIVE SUMMARY:" in text:
        sections["executive_summary"] = text.split("EXECUTIVE SUMMARY:")[1].split("THREAT ANALYSIS:")[0].strip()
    if "THREAT ANALYSIS:" in text:
        sections["threat_analysis"] = text.split("THREAT ANALYSIS:")[1].split("RECOMMENDATIONS:")[0].strip()
    if "RECOMMENDATIONS:" in text:
        rec_block = text.split("RECOMMENDATIONS:")[1].split("VERDICT:")[0].strip()
        sections["recommendations"] = [r.lstrip("- ").strip() for r in rec_block.split("\n") if r.strip()]
    return sections
