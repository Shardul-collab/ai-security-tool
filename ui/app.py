import streamlit as st
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.virustotal import scan_url as vt_url, scan_ip as vt_ip, scan_file as vt_file
from scanners.abuseipdb import check_ip
from scanners.urlscan import scan_url as us_url
from engine.risk_engine import calculate_risk
from ai.report_generator import generate_report

st.set_page_config(page_title="AI Security Assessment Tool", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.risk-safe     { background:#1a7a1a; color:white; padding:10px; border-radius:8px; text-align:center; font-size:1.5em; }
.risk-low      { background:#4a7a1a; color:white; padding:10px; border-radius:8px; text-align:center; font-size:1.5em; }
.risk-medium   { background:#7a5a00; color:white; padding:10px; border-radius:8px; text-align:center; font-size:1.5em; }
.risk-high     { background:#7a2a00; color:white; padding:10px; border-radius:8px; text-align:center; font-size:1.5em; }
.risk-critical { background:#7a0000; color:white; padding:10px; border-radius:8px; text-align:center; font-size:1.5em; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI-Powered Security Assessment Tool")
st.caption("Powered by VirusTotal · AbuseIPDB · URLScan · Gemini AI")
st.divider()

tab1, tab2 = st.tabs(["🔍 Scan", "📋 Results"])

if "results" not in st.session_state:
    st.session_state.results = None

with tab1:
    st.subheader("Submit Target for Analysis")
    scan_type = st.radio("Select input type:", ["URL", "IP Address", "File Upload"], horizontal=True)

    target = None
    file_bytes = None
    filename = None

    if scan_type == "URL":
        target = st.text_input("Enter URL", placeholder="https://example.com")
    elif scan_type == "IP Address":
        target = st.text_input("Enter IP Address", placeholder="8.8.8.8")
    else:
        uploaded = st.file_uploader("Upload file", type=["exe", "zip", "pdf"])
        if uploaded:
            file_bytes = uploaded.read()
            filename = uploaded.name
            target = filename

    if st.button("🚀 Run Security Scan", use_container_width=True):
        if not target:
            st.error("Please provide a target.")
        else:
            with st.spinner("Running security analysis..."):
                vt_result, abuse_result, urlscan_result = None, None, None
                progress = st.progress(0, text="Querying VirusTotal...")

                try:
                    if scan_type == "URL":
                        vt_result = vt_url(target)
                    elif scan_type == "IP Address":
                        vt_result = vt_ip(target)
                    else:
                        vt_result = vt_file(file_bytes, filename)
                except Exception as e:
                    st.warning(f"VirusTotal error: {e}")

                progress.progress(33, text="Querying AbuseIPDB...")
                try:
                    if scan_type == "IP Address":
                        abuse_result = check_ip(target)
                except Exception as e:
                    st.warning(f"AbuseIPDB error: {e}")

                progress.progress(66, text="Querying URLScan...")
                try:
                    if scan_type == "URL":
                        urlscan_result = us_url(target)
                except Exception as e:
                    st.warning(f"URLScan error: {e}")

                progress.progress(85, text="Calculating risk score...")
                risk = calculate_risk(vt_result, abuse_result, urlscan_result)

                progress.progress(95, text="Generating AI report...")
                report = generate_report(target, scan_type, risk, {})

                progress.progress(100, text="Done!")
                st.session_state.results = {
                    "target": target, "type": scan_type,
                    "risk": risk, "report": report,
                    "vt": vt_result, "abuse": abuse_result, "urlscan": urlscan_result
                }
                st.success("Scan complete! Go to the Results tab.")

with tab2:
    if not st.session_state.results:
        st.info("No scan results yet. Run a scan in the Scan tab.")
    else:
        r = st.session_state.results
        risk = r["risk"]
        report = r["report"]

        st.subheader(f"Results for: `{r['target']}`")

        level = risk["level"].lower().replace(" ", "-")
        st.markdown(f'<div class="risk-{level}">🔴 {risk["level"]} — Score: {risk["score"]}/100</div>', unsafe_allow_html=True)
        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🤖 Executive Summary")
            st.write(report.get("executive_summary", "N/A"))
            st.markdown("### 🔬 Threat Analysis")
            st.write(report.get("threat_analysis", "N/A"))
            st.markdown("### ✅ Recommendations")
            for rec in report.get("recommendations", []):
                st.markdown(f"- {rec}")

        with col2:
            st.markdown("### 🚩 Risk Flags")
            if risk["flags"]:
                for flag in risk["flags"]:
                    st.error(flag)
            else:
                st.success("No flags detected")

            st.markdown("### 📡 Raw API Data")
            with st.expander("VirusTotal"):
                st.json(r["vt"] or {})
            with st.expander("AbuseIPDB"):
                st.json(r["abuse"] or {})
            with st.expander("URLScan"):
                st.json(r["urlscan"] or {})
