import streamlit as st
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import re
import io
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# -------------------------------------------------
# Page Config
# -------------------------------------------------
st.set_page_config(
    page_title="CyberWatch – AI Security Operations Dashboard",
    layout="wide"
)

# -------------------------------------------------
# 🌙 DARK SOC THEME (GLASS STYLE)
# -------------------------------------------------
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top, #020617, #020617 40%, #020617);
    color: #e5e7eb;
}
h1,h2,h3,h4 { color:#e5e7eb; }
.card {
    background: linear-gradient(145deg, #020617, #020617);
    border: 1px solid #1e293b;
    border-radius: 18px;
    padding: 22px;
    box-shadow: 0 0 35px rgba(59,130,246,0.25);
    margin-bottom:20px;
}
.metric-card {
    background:#020617;
    border:1px solid #1e293b;
    border-radius:18px;
    padding:20px;
    box-shadow:0 0 25px rgba(59,130,246,0.25);
    text-align:center;
}
.badge-critical {
    background:linear-gradient(135deg,#3f1d2b,#1f0f16);
    border:1px solid #7f1d1d;
    border-radius:16px;
    padding:18px;
    width:100%;
}
.badge-high {
    background:linear-gradient(135deg,#3a2a14,#1f160a);
    border:1px solid #92400e;
    border-radius:16px;
    padding:18px;
    width:100%;
}
.host-row {
    background:#020617;
    border:1px solid #1e293b;
    border-radius:12px;
    padding:12px 16px;
    margin-bottom:10px;
    display:flex;
    justify-content:space-between;
}
.stButton>button {
    background:#020617;
    color:#e5e7eb;
    border:1px solid #334155;
    border-radius:12px;
    padding:8px 16px;
}
.stButton>button:hover { background:#1e293b; }
</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# HEADER
# -------------------------------------------------
st.markdown("""
<div class="card" style="display:flex;justify-content:space-between;align-items:center;">
<div>
<h1>🛡️ CyberWatch</h1>
<p style="color:#38bdf8;">AI Security Operations Dashboard</p>
</div>
<div style="display:flex;align-items:center;gap:8px;">
<div style="width:10px;height:10px;background:#22c55e;border-radius:50%;"></div>
<span style="color:#86efac;font-size:14px;">LIVE SOC</span>
</div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------
# SAFE EMPTY DATA + SAMPLE DATA + PARSER
# -------------------------------------------------
def safe_empty_df():
    return pd.DataFrame({"Alert_Type": [], "Host_Name": [], "Date_Time": [], "Severity": []})

if "data" not in st.session_state:
    st.session_state.data = safe_empty_df()

def load_sample_data():
    return pd.DataFrame({
        "Alert_Type": ["Malware","Network","Authentication","Malware","Network"],
        "Host_Name": ["SERVER-APP-03","FIREWALL-EDGE-01","SERVER-DB-02","SERVER-APP-03","WORKSTATION-HR"],
        "Date_Time": ["2025-12-13","2025-12-14","2025-12-15","2025-12-16","2025-12-17"],
        "Severity": ["Critical","High","Medium","High","Low"]
    })

def extract_alert_type(text):
    t = text.lower()
    if any(x in t for x in ["malware","virus","trojan","ransom"]): return "Malware"
    if any(x in t for x in ["network","ddos","scan","traffic"]): return "Network"
    if any(x in t for x in ["auth","login","password","credential"]): return "Authentication"
    return "General"

def extract_severity(text):
    t = text.lower()
    if any(x in t for x in ["critical","crit","emergency","fatal"]): return "Critical"
    if any(x in t for x in ["high","severe","major"]): return "High"
    if any(x in t for x in ["medium","warning","warn"]): return "Medium"
    return "Low"

def extract_host(text):
    match = re.search(r"(server[-_a-z0-9]+|workstation[-_a-z0-9]+|firewall[-_a-z0-9]+|\d+\.\d+\.\d+\.\d+)", text, re.I)
    return match.group(0).upper() if match else "UNKNOWN-HOST"

def extract_date(text):
    match = re.search(r"\d{4}-\d{2}-\d{2}", text)
    return match.group(0) if match else datetime.now().strftime("%Y-%m-%d")

def parse_any_file(uploaded_file):
    try:
        text = uploaded_file.read().decode("utf-8", errors="ignore")
        if not text.strip():
            return safe_empty_df()
        records = []
        for line in text.splitlines():
            records.append({
                "Alert_Type": extract_alert_type(line),
                "Host_Name": extract_host(line),
                "Date_Time": extract_date(line),
                "Severity": extract_severity(line)
            })
        return pd.DataFrame(records)
    except:
        return safe_empty_df()

# -------------------------------------------------
# CONTROLS + FILTER PANEL
# -------------------------------------------------
c1,c2,c3 = st.columns(3)
with c1:
    uploaded = st.file_uploader("📂 Upload ANY file", type=None)
with c2:
    if st.button("🔄 Load Sample Data"):
        st.session_state.data = load_sample_data()
with c3:
    if st.button("🧹 Clear All"):
        st.session_state.data = safe_empty_df()

if uploaded:
    st.session_state.data = parse_any_file(uploaded)

df = st.session_state.data

st.markdown("<div class='card'><h3>🔍 Filter Alerts</h3>", True)
f1,f2,f3 = st.columns(3)
with f1:
    severity_filter = st.multiselect("Severity", sorted(df["Severity"].unique()), sorted(df["Severity"].unique()))
with f2:
    alert_filter = st.multiselect("Alert Type", sorted(df["Alert_Type"].unique()), sorted(df["Alert_Type"].unique()))
with f3:
    host_filter = st.multiselect("Host", sorted(df["Host_Name"].unique()), sorted(df["Host_Name"].unique()))
st.markdown("</div>", True)

filtered_df = df[
    df["Severity"].isin(severity_filter) &
    df["Alert_Type"].isin(alert_filter) &
    df["Host_Name"].isin(host_filter)
]

# -------------------------------------------------
# RISK SCORE + STATS + KPI CARDS
# -------------------------------------------------
def calculate_risk_score(df):
    score = 0
    score += len(df[df["Severity"]=="Critical"]) * 40
    score += len(df[df["Severity"]=="High"]) * 25
    score += len(df[df["Severity"]=="Medium"]) * 15
    score += len(df[df["Severity"]=="Low"]) * 5
    score += len(df[df["Alert_Type"]=="Malware"]) * 20
    score += df["Host_Name"].nunique() * 10
    return min(score,100)

risk_score = calculate_risk_score(filtered_df)

total = len(filtered_df)
critical = len(filtered_df[filtered_df["Severity"]=="Critical"])
high = len(filtered_df[filtered_df["Severity"]=="High"])
malware = len(filtered_df[filtered_df["Alert_Type"]=="Malware"])

k1,k2,k3,k4 = st.columns(4)
k1.markdown(f"<div class='metric-card'><h4>Total Alerts</h4><h2>{total}</h2></div>",True)
k2.markdown(f"<div class='metric-card'><h4>Critical Alerts</h4><h2>{critical}</h2></div>",True)
k3.markdown(f"<div class='metric-card'><h4>Malware Alerts</h4><h2>{malware}</h2></div>",True)
k4.markdown(f"<div class='metric-card'><h4>⚠ Risk Score</h4><h2>{risk_score}/100</h2></div>",True)

# -------------------------------------------------
# CHARTS
# -------------------------------------------------
st.markdown("<div class='card'><h3>Alert Type Distribution</h3>",True)
if total:
    fig,ax = plt.subplots()
    filtered_df["Alert_Type"].value_counts().plot.pie(
        autopct="%1.0f%%", startangle=90, wedgeprops={"width":0.4}, ax=ax)
    ax.set_ylabel("")
    st.pyplot(fig)
else:
    st.info("No data")
st.markdown("</div>",True)

st.markdown("<div class='card'><h3>Host-Wise Alerts</h3>",True)
if total:
    st.bar_chart(filtered_df["Host_Name"].value_counts())
else:
    st.info("No data")
st.markdown("</div>",True)

st.markdown("<div class='card'><h3>Alerts Over Time</h3>",True)
if total:
    st.line_chart(filtered_df.groupby("Date_Time").size())
else:
    st.info("No data")
st.markdown("</div>",True)

# -------------------------------------------------
# AI SOC SUMMARY
# -------------------------------------------------
top_hosts = filtered_df["Host_Name"].value_counts().head(4)

st.markdown(f"""
<div class="card">
<h3>🤖 CyberWatch AI SOC Summary</h3>

<div style="display:flex;gap:16px;margin:16px 0;">
    <div class="badge-critical">🚨 Critical<br><span style="font-size:36px;">{critical}</span></div>
    <div class="badge-high">🛡️ High<br><span style="font-size:36px;">{high}</span></div>
</div>

<p style="font-size:15px;line-height:1.5;">
    <strong>Overall Risk Score:</strong> <span style="color:#f97316;font-weight:bold;">{risk_score}/100</span>
</p>

<p style="line-height:1.55;color:#d1d5db;">
Based on the observed alert patterns, the detected activities align with common attacker behaviors 
described in the <strong>MITRE ATT&CK framework</strong>. 
Malware-related alerts indicate potential malicious code execution, 
while authentication-related events suggest attempts to misuse or compromise credentials. 
Network-based alerts may represent reconnaissance or scanning activities performed by an attacker.
</p>

<h4 style="margin:24px 0 12px 0;color:#94a3b8;">Top Affected Hosts</h4>
""", unsafe_allow_html=True)

for host, count in top_hosts.items():
    st.markdown(f"""
    <div class="host-row">
        <span style="color:#e5e7eb;">{host}</span>
        <span style="color:#f87171;font-weight:bold;">{count} alerts</span>
    </div>
    """, unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

# -------------------------------------------------
# MITRE ATT&CK CONTEXT (PARAGRAPH CARD)
# -------------------------------------------------
st.markdown("""
<div class="card">
<h3>🧠 MITRE ATT&CK Context</h3>

<p>
The alert patterns observed across endpoints and network infrastructure
show alignment with common adversary behaviors defined in the
MITRE ATT&CK framework.
</p>

<p>
Malware-related alerts indicate potential execution of malicious payloads,
while authentication anomalies suggest possible credential access attempts.
Network-based alerts may represent reconnaissance or scanning activity
performed during early attack stages.
</p>

<p>
This contextual mapping helps security teams understand not just
<b>what happened</b>, but also <b>how an attacker may be operating</b>,
supporting faster investigation and informed response decisions.
</p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------
# NEW STRUCTURED MITRE ATT&CK MAPPING TABLE (exactly as requested)
# -------------------------------------------------
st.markdown("""
<div class="card">
<h3>🧩 MITRE ATT&CK Mapping</h3>

<table style="width:100%;border-collapse:collapse;">
<tr style="color:#38bdf8;">
<th align="left">Tactic</th>
<th align="left">Technique ID</th>
<th align="left">Technique Name</th>
<th align="left">Observed Evidence</th>
</tr>

<tr>
<td>Execution</td>
<td>T1059</td>
<td>Command and Scripting Interpreter</td>
<td>Malware-related alerts detected on endpoints</td>
</tr>

<tr>
<td>Credential Access</td>
<td>T1110</td>
<td>Brute Force</td>
<td>Authentication anomalies and failed login attempts</td>
</tr>

<tr>
<td>Discovery</td>
<td>T1046</td>
<td>Network Service Scanning</td>
<td>Repeated network scanning and reconnaissance alerts</td>
</tr>

<tr>
<td>Initial Access</td>
<td>T1190</td>
<td>Exploit Public-Facing Application</td>
<td>External network activity targeting exposed services</td>
</tr>
</table>

<p style="margin-top:12px;color:#94a3b8;">
This structured mapping aligns observed alert behavior with
recognized adversary techniques from the MITRE ATT&CK framework,
enabling tactical understanding of attacker activity.
</p>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------
# PDF EXPORT
# -------------------------------------------------
def generate_pdf(df, risk_score):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 60
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "CyberWatch – SOC Report")
    y -= 35

    c.setFont("Helvetica", 10)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   |   Total Alerts: {len(df)}")
    y -= 40

    c.setFillColorRGB(0,0,0)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Key Statistics")
    y -= 20

    c.setFont("Helvetica", 11)
    c.drawString(60, y, f"• Critical Alerts: {len(df[df['Severity']=='Critical'])}"); y -= 18
    c.drawString(60, y, f"• High Alerts:     {len(df[df['Severity']=='High'])}");     y -= 18
    c.drawString(60, y, f"• Risk Score:       {risk_score}/100");                    y -= 30

    c.save()
    buffer.seek(0)
    return buffer

pdf_buffer = generate_pdf(filtered_df, risk_score)

st.download_button(
    label="📄 Export SOC Report (PDF)",
    data=pdf_buffer,
    file_name="CyberWatch_SOC_Report.pdf",
    mime="application/pdf"
)

# -------------------------------------------------
# FOOTER
# -------------------------------------------------
st.markdown("""
<hr style="border:1px solid #1e293b;margin-top:40px;">
<p style="text-align:center;color:#64748b;font-size:13px;">
CyberWatch © 2025 | AI Security Operations Dashboard
</p>
""", unsafe_allow_html=True)
