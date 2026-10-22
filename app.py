
import os
import re
import json
import base64
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import pandas as pd
import requests
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
VT_BASE_URL = "https://www.virustotal.com/api/v3"

st.set_page_config(
    page_title="ThreatLens | SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- SOC DESIGN ----------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    :root {
        --bg: #080d18;
        --panel: #101827;
        --border: #233147;
        --text: #e8eef8;
        --muted: #93a4bb;
        --teal: #2dd4bf;
        --blue: #60a5fa;
    }

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background: var(--bg);
        color: var(--text);
    }

    [data-testid="stHeader"] {
        background: rgba(8, 13, 24, 0.92);
    }

    [data-testid="stSidebar"] {
        background: #0c1422;
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] * {
        color: var(--text);
    }

    .block-container {
        padding-top: 1.8rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    h1, h2, h3 {
        color: var(--text) !important;
        letter-spacing: -0.5px;
    }

    p, label, .stCaption {
        color: var(--muted);
    }

    div[data-testid="stMetric"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 18px 20px;
    }

    div[data-testid="stMetricLabel"] {
        color: var(--muted);
        font-size: 0.85rem;
    }

    div[data-testid="stMetricValue"] {
        color: var(--text);
        font-weight: 700;
    }

    div[data-testid="stForm"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 22px;
    }

    .tl-brand {
        font-size: 1.5rem;
        font-weight: 800;
        letter-spacing: -0.8px;
        color: var(--text);
        padding: 8px 0 2px 0;
    }

    .tl-brand span {
        color: var(--teal);
    }

    .tl-subtitle {
        color: var(--muted);
        font-size: 0.82rem;
        margin-bottom: 22px;
    }

    .tl-eyebrow {
        color: var(--teal);
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 2px;
        text-transform: uppercase;
    }

    .tl-panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 20px;
        margin-bottom: 12px;
    }

    .tl-panel-title {
        font-size: 1rem;
        font-weight: 700;
        color: var(--text);
        margin-bottom: 12px;
    }

    .tl-muted {
        color: var(--muted);
        font-size: 0.85rem;
    }

    div.stButton > button,
    div.stFormSubmitButton > button,
    div.stDownloadButton > button {
        border-radius: 9px;
        border: 1px solid #277f7a;
        background: #123c42;
        color: #d9fffa;
        font-weight: 600;
        min-height: 42px;
    }

    div.stButton > button:hover,
    div.stFormSubmitButton > button:hover,
    div.stDownloadButton > button:hover {
        border-color: var(--teal);
        background: #18545a;
        color: white;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
    }

    hr {
        border-color: var(--border);
    }

    #MainMenu, footer {
        visibility: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------- SESSION STATE ----------
if "history" not in st.session_state:
    st.session_state.history = []

if "last_report" not in st.session_state:
    st.session_state.last_report = None

# ---------- IOC VALIDATION ----------
def validate_ioc(ioc_type, value):
    value = value.strip()

    if ioc_type == "IP Address":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if ioc_type == "Domain":
        pattern = (
            r"(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,63}"
        )
        return bool(re.fullmatch(pattern, value))

    if ioc_type == "URL":
        parsed = urlparse(value)
        return (
            parsed.scheme in ("http", "https")
            and bool(parsed.netloc)
        )

    if ioc_type == "File Hash":
        return bool(
            re.fullmatch(
                r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})",
                value,
            )
        )

    return False


# ---------- VIRUSTOTAL LOOKUP ----------
def investigate_ioc(ioc_type, value):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key missing. Check your .env file."}

    headers = {"x-apikey": VT_API_KEY}
    value = value.strip()

    if ioc_type == "IP Address":
        endpoint = f"/ip_addresses/{value}"
    elif ioc_type == "Domain":
        endpoint = f"/domains/{value}"
    elif ioc_type == "URL":
        url_id = base64.urlsafe_b64encode(
            value.encode()
        ).decode().rstrip("=")
        endpoint = f"/urls/{url_id}"
    else:
        endpoint = f"/files/{value}"

    try:
        response = requests.get(
            VT_BASE_URL + endpoint,
            headers=headers,
            timeout=25,
        )

        if response.status_code == 401:
            return {"error": "API key rejected. Check your .env file."}
        if response.status_code == 403:
            return {"error": "VirusTotal access denied or quota unavailable."}
        if response.status_code == 404:
            return {"error": "Indicator not found in VirusTotal."}
        if response.status_code == 429:
            return {"error": "Rate limit reached. Please wait and retry."}

        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        if malicious > 0:
            risk = "High"
        elif suspicious > 0:
            risk = "Medium"
        elif total > 0:
            risk = "Low"
        else:
            risk = "Unknown"

        score = (
            round(100 * (1 - (malicious + suspicious) / total))
            if total > 0 else None
        )

        return {
            "risk": risk,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "score": score,
            "reputation": attributes.get("reputation", "N/A"),
            "stats": stats,
        }

    except requests.Timeout:
        return {"error": "VirusTotal request timed out. Try again."}
    except requests.RequestException as exc:
        return {"error": f"Network/API error: {exc}"}
    except (ValueError, TypeError) as exc:
        return {"error": f"Could not read API response: {exc}"}


# ---------- REUSABLE DISPLAY HELPERS ----------
def section_header(title, subtitle=""):
    st.markdown(f"### {title}")
    if subtitle:
        st.caption(subtitle)


def risk_color(risk):
    return {
        "High": "#fb7185",
        "Medium": "#fbbf24",
        "Low": "#2dd4bf",
        "Unknown": "#93a4bb",
    }.get(risk, "#93a4bb")

# ---------- SIDEBAR & NAVIGATION ----------
with st.sidebar:
    st.markdown(
        '<div class="tl-brand">🛡️ Threat<span>Lens</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="tl-subtitle">SECURITY OPERATIONS CENTER</div>',
        unsafe_allow_html=True,
    )

    st.markdown("##### WORKSPACE")
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "IOC Investigation",
            "Investigation History",
            "About ThreatLens",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("##### PLATFORM STATUS")

    if VT_API_KEY:
        st.markdown("🟢 **API key configured**")
    else:
        st.markdown("🔴 **API key missing**")

    st.markdown("🟢 **ThreatLens interface active**")
    st.markdown("---")
    st.caption("ThreatLens SOC Platform")
    st.caption("Educational security investigation tool")


# ---------- OVERVIEW DASHBOARD ----------
if page == "Overview":
    st.markdown(
        '<div class="tl-eyebrow">SECURITY OPERATIONS CENTER</div>',
        unsafe_allow_html=True,
    )
    st.title("Threat Intelligence Overview")
    st.caption(
        "Monitor investigations, review indicator risk and explore "
        "threat intelligence findings."
    )

    history = st.session_state.history
    total_cases = len(history)
    high_cases = sum(1 for item in history if item["Risk"] == "High")
    medium_cases = sum(1 for item in history if item["Risk"] == "Medium")
    low_cases = sum(1 for item in history if item["Risk"] == "Low")
    unknown_cases = sum(1 for item in history if item["Risk"] == "Unknown")

    st.markdown("### Investigation Summary")
    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Investigations", total_cases)
    c2.metric("High Risk", high_cases)
    c3.metric("Medium Risk", medium_cases)
    c4.metric("Low Risk", low_cases)

    st.markdown("---")

    left, right = st.columns([1.15, 1])

    with left:
        with st.container(border=True):
            section_header(
                "Risk Distribution",
                "Risk classifications from this session's investigations.",
            )

            if history:
                risk_df = pd.DataFrame(
                    [
                        {"Risk": "High", "Count": high_cases},
                        {"Risk": "Medium", "Count": medium_cases},
                        {"Risk": "Low", "Count": low_cases},
                        {"Risk": "Unknown", "Count": unknown_cases},
                    ]
                )
                risk_df = risk_df[risk_df["Count"] > 0]

                fig = px.pie(
                    risk_df,
                    names="Risk",
                    values="Count",
                    hole=0.68,
                    color="Risk",
                    color_discrete_map={
                        "High": "#fb7185",
                        "Medium": "#fbbf24",
                        "Low": "#2dd4bf",
                        "Unknown": "#64748b",
                    },
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e8eef8",
                    legend_title_text="Severity",
                    margin=dict(t=15, b=15, l=10, r=10),
                    height=300,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info(
                    "No investigations yet. Start an IOC investigation "
                    "to populate your security dashboard."
                )

    with right:
        with st.container(border=True):
            section_header(
                "Detection Summary",
                "Aggregated detections from recorded investigations.",
            )

            if history:
                malicious_sum = sum(
                    int(item["Malicious"]) for item in history
                )
                suspicious_sum = sum(
                    int(item["Suspicious"]) for item in history
                )
                harmless_sum = sum(
                    int(item["Harmless"]) for item in history
                )
                undetected_sum = sum(
                    int(item["Undetected"]) for item in history
                )

                st.metric("Malicious detections", malicious_sum)
                st.metric("Suspicious detections", suspicious_sum)
                st.metric("Harmless detections", harmless_sum)
                st.metric("Undetected results", undetected_sum)
            else:
                st.info("Detection statistics will appear after your first lookup.")

    st.markdown("---")
    section_header(
        "Recent Investigations",
        "The latest indicators analyzed during this session.",
    )

    if history:
        recent_df = pd.DataFrame(history[-10:][::-1])
        st.dataframe(
            recent_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Your investigation activity will appear here.")

    st.caption(
        "Metrics are based on the current Streamlit session. "
        "They are not a global or persistent incident database."
    )

# ---------- IOC INVESTIGATION PAGE ----------
elif page == "IOC Investigation":
    st.markdown(
        '<div class="tl-eyebrow">THREAT ANALYSIS / IOC LOOKUP</div>',
        unsafe_allow_html=True,
    )
    st.title("IOC Investigation")
    st.caption(
        "Analyze indicators of compromise against live VirusTotal intelligence."
    )

    with st.container(border=True):
        st.markdown("### Submit an Indicator")
        st.write(
            "Choose the indicator type and enter its value to begin analysis."
        )

        with st.form("ioc_investigation_form"):
            ioc_type = st.selectbox(
                "Indicator Type",
                ["IP Address", "Domain", "URL", "File Hash"],
            )

            value = st.text_input(
                "Indicator Value",
                placeholder="Example: 8.8.8.8",
                help="Enter one IP address, domain, URL, or file hash.",
            )

            submitted = st.form_submit_button(
                "🔎 Analyze Indicator",
                type="primary",
                use_container_width=True,
            )

    if submitted:
        value = value.strip()

        if not value:
            st.error("Enter an indicator value first.")

        elif not validate_ioc(ioc_type, value):
            st.error(f"Invalid {ioc_type} format. Check the value.")

        else:
            with st.spinner("Querying VirusTotal threat intelligence..."):
                result = investigate_ioc(ioc_type, value)

            if "error" in result:
                st.error(result["error"])

            else:
                timestamp = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )

                report = {
                    "Timestamp": timestamp,
                    "Indicator": value,
                    "Type": ioc_type,
                    "Risk": result["risk"],
                    "Reputation Score": result["score"],
                    "Malicious": result["malicious"],
                    "Suspicious": result["suspicious"],
                    "Harmless": result["harmless"],
                    "Undetected": result["undetected"],
                    "Total Engines": result["total"],
                    "Community Reputation": result["reputation"],
                }

                st.session_state.history.append(report)
                st.session_state.last_report = report

    # Show the latest report when available, including after page reruns.
    report = st.session_state.last_report

    if report:
        st.markdown("---")
        st.markdown("### Investigation Results")

        result_cols = st.columns([1.4, 1, 1])
        with result_cols[0]:
            st.markdown("**Indicator**")
            st.code(report["Indicator"])

        with result_cols[1]:
            st.markdown("**Indicator Type**")
            st.write(report["Type"])

        with result_cols[2]:
            st.markdown("**Last Investigation**")
            st.caption(report["Timestamp"])

        risk = report["Risk"]
        score = report["Reputation Score"]
        color = risk_color(risk)

        st.markdown(
            f"""
            <div class="tl-panel" style="border-left: 4px solid {color};">
                <div class="tl-eyebrow">THREAT ASSESSMENT</div>
                <div style="font-size: 1.8rem; font-weight: 800;
                            color: {color}; margin: 8px 0;">
                    {risk.upper()} RISK
                </div>
                <div class="tl-muted">
                    ThreatLens-calculated reputation score
                </div>
                <div style="font-size: 2.2rem; font-weight: 800;
                            color: #e8eef8; margin-top: 5px;">
                    {str(score) + "/100" if score is not None else "N/A"}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### Detection Statistics")
        a, b, c, d = st.columns(4)
        a.metric("Malicious", report["Malicious"])
        b.metric("Suspicious", report["Suspicious"])
        c.metric("Harmless", report["Harmless"])
        d.metric("Undetected", report["Undetected"])

        with st.container(border=True):
            st.markdown("### Additional Intelligence")
            x, y = st.columns(2)
            x.metric("Total Engines", report["Total Engines"])
            y.metric("Community Reputation", report["Community Reputation"])

        st.caption(
            "The score is calculated by ThreatLens, not officially "
            "provided by VirusTotal. Zero detections do not guarantee safety. "
            "Results reflect the recorded investigation; check the timestamp "
            "before interpreting older results."
        )

        json_bytes = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
        ).encode("utf-8")

        st.download_button(
            "⬇️ Download This Investigation (JSON)",
            data=json_bytes,
            file_name="threatlens_investigation.json",
            mime="application/json",
        )
    else:
        st.info("Submit an indicator above to view its investigation report.")

# ---------- INVESTIGATION HISTORY PAGE ----------
elif page == "Investigation History":
    st.markdown(
        '<div class="tl-eyebrow">SECURITY OPERATIONS / RECORDS</div>',
        unsafe_allow_html=True,
    )
    st.title("Investigation History")
    st.caption(
        "Review previous IOC lookups and export investigation records."
    )

    history = st.session_state.history

    if history:
        col1, col2 = st.columns([3, 1])

        with col1:
            st.metric("Recorded Investigations", len(history))

        with col2:
            st.metric(
                "High-Risk Indicators",
                sum(1 for item in history if item["Risk"] == "High"),
            )

        st.markdown("### Investigation Records")
        df = pd.DataFrame(history[::-1])

        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("### Export Reports")
        export1, export2 = st.columns(2)

        with export1:
            csv_data = pd.DataFrame(history).to_csv(
                index=False
            ).encode("utf-8")

            st.download_button(
                "⬇️ Download History (CSV)",
                data=csv_data,
                file_name="threatlens_history.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with export2:
            selected_index = st.selectbox(
                "Select a report for JSON export",
                range(len(history)),
                format_func=lambda i: (
                    f"{history[i]['Indicator']} | "
                    f"{history[i]['Risk']} | "
                    f"{history[i]['Timestamp']}"
                ),
            )

            selected_report = history[selected_index]
            json_data = json.dumps(
                selected_report,
                indent=4,
                ensure_ascii=False,
            ).encode("utf-8")

            st.download_button(
                "⬇️ Download Selected Report (JSON)",
                data=json_data,
                file_name="threatlens_report.json",
                mime="application/json",
                use_container_width=True,
            )

        st.markdown("---")
        if st.button("Clear Session History", type="secondary"):
            st.session_state.history = []
            st.session_state.last_report = None
            st.rerun()

        st.caption(
            "Clearing history removes these records from the current "
            "Streamlit session. Download reports first if you need to keep them."
        )

    else:
        st.info("No investigation records are available yet.")
        st.caption(
            "Run an IOC investigation to populate this page."
        )


# ---------- ABOUT THREATLENS PAGE ----------
elif page == "About ThreatLens":
    st.markdown(
        '<div class="tl-eyebrow">PLATFORM INFORMATION</div>',
        unsafe_allow_html=True,
    )
    st.title("About ThreatLens")
    st.caption(
        "Automated Threat Intelligence and Incident Investigation Platform"
    )

    with st.container(border=True):
        st.markdown("### Platform Overview")
        st.write(
            "ThreatLens is a Python-based cybersecurity dashboard that "
            "uses the VirusTotal API v3 to retrieve intelligence about "
            "indicators of compromise (IOCs). It provides a central "
            "interface for reviewing detection results, assessing severity "
            "and exporting investigation reports."
        )

    st.markdown("### Core Capabilities")

    feature_cols = st.columns(2)

    with feature_cols[0]:
        with st.container(border=True):
            st.markdown("#### 🔎 IOC Analysis")
            st.write(
                "Investigate IP addresses, domains, URLs and file hashes "
                "with input validation and live API lookups."
            )

        with st.container(border=True):
            st.markdown("#### 📊 Threat Assessment")
            st.write(
                "Review malicious, suspicious, harmless and undetected "
                "engine counts, plus a ThreatLens-calculated score."
            )

    with feature_cols[1]:
        with st.container(border=True):
            st.markdown("#### 📋 Investigation Records")
            st.write(
                "Review current-session investigations and export "
                "records in CSV or JSON format."
            )

        with st.container(border=True):
            st.markdown("#### 🛡️ Security Operations")
            st.write(
                "Use a centralized SOC-inspired dashboard to review "
                "investigation activity and risk classifications."
            )

    st.markdown("### Technology Stack")
    st.write(
        "**Python** · **Streamlit** · **Pandas** · "
        "**Plotly** · **Requests** · **VirusTotal API v3**"
    )

    st.markdown("### Important Limitations")
    st.warning(
        "VirusTotal access and rate limits depend on your account. "
        "A zero-detection result does not prove that an indicator is safe. "
        "The reputation score is calculated by ThreatLens and is not an "
        "official VirusTotal score. History is held in the current session, "
        "not a persistent database."
    )

    st.caption(
        "ThreatLens | Educational and authorized defensive security use"
    )
