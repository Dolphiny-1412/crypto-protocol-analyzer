# app.py
# Streamlit web interface for the Cryptographic Protocol Analyzer.
#
# Run with:
#   streamlit run app.py

import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os

from analyzer import analyze_pcap, run_demo_analysis
from report_generator import (
    findings_to_dataframe,
    compute_summary,
    dataframe_to_csv_bytes,
    severity_chart_data,
)
from rules import SEVERITY_COLORS

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Crypto Protocol Analyzer",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark security-tool aesthetic
# ---------------------------------------------------------------------------
st.markdown("""
<style>
/* ── Global font & background ── */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0d1117;
    color: #e6edf3;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}
section[data-testid="stSidebar"] * { color: #e6edf3 !important; }

/* ── Main header ── */
.main-header {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.9rem;
    font-weight: 700;
    color: #58a6ff;
    letter-spacing: 0.02em;
    padding-bottom: 0.2rem;
    border-bottom: 2px solid #21262d;
    margin-bottom: 1.5rem;
}
.sub-header {
    color: #8b949e;
    font-size: 0.9rem;
    margin-top: -1rem;
    margin-bottom: 1.5rem;
}

/* ── Metric cards ── */
.metric-row { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
.metric-card {
    flex: 1;
    min-width: 130px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    text-align: center;
}
.metric-card .metric-label {
    font-size: 0.72rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.3rem;
}
.metric-card .metric-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
}
.metric-card.critical .metric-value { color: #ff3b30; }
.metric-card.high     .metric-value { color: #ff9500; }
.metric-card.medium   .metric-value { color: #ffcc00; }
.metric-card.low      .metric-value { color: #34c759; }
.metric-card.total    .metric-value { color: #58a6ff; }
.metric-card.packets  .metric-value { color: #e6edf3; }

/* ── Section headers ── */
.section-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    font-weight: 700;
    color: #58a6ff;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin: 1.5rem 0 0.5rem 0;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid #21262d;
}

/* ── Severity badges ── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.05em;
}
.badge-critical { background:#3d0a0a; color:#ff3b30; border:1px solid #ff3b30; }
.badge-high     { background:#3d1f00; color:#ff9500; border:1px solid #ff9500; }
.badge-medium   { background:#3d3000; color:#ffcc00; border:1px solid #ffcc00; }
.badge-low      { background:#0a2d15; color:#34c759; border:1px solid #34c759; }
.badge-info     { background:#0a1f3d; color:#58a6ff; border:1px solid #58a6ff; }

/* ── Finding card ── */
.finding-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.8rem;
}
.finding-card.critical { border-left: 4px solid #ff3b30; }
.finding-card.high     { border-left: 4px solid #ff9500; }
.finding-card.medium   { border-left: 4px solid #ffcc00; }
.finding-card.low      { border-left: 4px solid #34c759; }
.finding-card .finding-title {
    font-weight: 600;
    font-size: 0.95rem;
    margin-bottom: 0.5rem;
}
.finding-card .meta-row {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #8b949e;
    margin-bottom: 0.6rem;
}
.finding-card .explanation { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.5rem; }
.finding-card .recommendation {
    font-size: 0.82rem;
    color: #58a6ff;
    background: #0d1f33;
    border-radius: 6px;
    padding: 0.4rem 0.7rem;
}

/* ── Demo banner ── */
.demo-banner {
    background: #1a1f2e;
    border: 1px solid #3b4263;
    border-radius: 10px;
    padding: 0.8rem 1.2rem;
    color: #79b8ff;
    font-size: 0.85rem;
    margin-bottom: 1rem;
}

/* ── Upload zone ── */
[data-testid="stFileUploader"] {
    background: #161b22 !important;
    border: 1px dashed #30363d !important;
    border-radius: 10px !important;
}

/* ── Buttons ── */
.stButton > button {
    background: #21262d;
    color: #58a6ff;
    border: 1px solid #30363d;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    transition: all 0.15s;
}
.stButton > button:hover {
    background: #1f6feb22;
    border-color: #58a6ff;
}

/* ── DataTable ── */
[data-testid="stDataFrame"] {
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid #30363d;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def badge_html(severity: str) -> str:
    cls = f"badge-{severity.lower()}"
    return f'<span class="badge {cls}">{severity.upper()}</span>'


def render_metric_cards(summary: dict):
    html = f"""
    <div class="metric-row">
      <div class="metric-card packets">
        <div class="metric-label">Packets Analyzed</div>
        <div class="metric-value">{summary['total_packets']:,}</div>
      </div>
      <div class="metric-card total">
        <div class="metric-label">Total Findings</div>
        <div class="metric-value">{summary['total_findings']}</div>
      </div>
      <div class="metric-card critical">
        <div class="metric-label">Critical</div>
        <div class="metric-value">{summary['critical']}</div>
      </div>
      <div class="metric-card high">
        <div class="metric-label">High</div>
        <div class="metric-value">{summary['high']}</div>
      </div>
      <div class="metric-card medium">
        <div class="metric-label">Medium</div>
        <div class="metric-value">{summary['medium']}</div>
      </div>
      <div class="metric-card low">
        <div class="metric-label">Low</div>
        <div class="metric-value">{summary['low']}</div>
      </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_finding_cards(findings: list):
    for f in findings:
        sev = f.get("severity", "Low").lower()
        badge = badge_html(f.get("severity", "Low"))
        meta = (
            f"<b>Protocol:</b> {f.get('protocol','N/A')} &nbsp;|&nbsp; "
            f"<b>Transport:</b> {f.get('transport','TCP')} &nbsp;|&nbsp; "
            f"<b>Src:</b> {f.get('src_ip','?')}:{f.get('src_port','')} &nbsp;→&nbsp; "
            f"<b>Dst:</b> {f.get('dst_ip','?')}:{f.get('dst_port','')}"
        )
        html = f"""
        <div class="finding-card {sev}">
          <div class="finding-title">{badge} &nbsp; {f.get('issue','')}</div>
          <div class="meta-row">{meta}</div>
          <div class="explanation">{f.get('explanation','')}</div>
          <div class="recommendation">💡 {f.get('recommendation','')}</div>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)


def render_severity_chart(result: dict):
    chart_df = severity_chart_data(result)
    color_map = {
        "Critical": "#ff3b30",
        "High":     "#ff9500",
        "Medium":   "#ffcc00",
        "Low":      "#34c759",
    }
    fig = px.bar(
        chart_df,
        x="Severity", y="Count",
        color="Severity",
        color_discrete_map=color_map,
        text="Count",
    )
    fig.update_layout(
        paper_bgcolor="#0d1117",
        plot_bgcolor="#161b22",
        font=dict(family="JetBrains Mono, monospace", color="#e6edf3", size=12),
        showlegend=False,
        margin=dict(l=20, r=20, t=20, b=20),
        xaxis=dict(gridcolor="#21262d"),
        yaxis=dict(gridcolor="#21262d"),
    )
    fig.update_traces(textposition="outside", marker_line_width=0)
    st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### 🔐 Crypto Protocol Analyzer")
    st.markdown("---")
    st.markdown(
        "**Upload** a `.pcap` or `.pcapng` file to analyze real network traffic, "
        "or click **Run Demo** to explore sample findings."
    )
    st.markdown("---")
    st.markdown("**Detected Threats**")
    threats = [
        ("🔴", "Telnet / FTP / TFTP"),
        ("🟠", "Weak TLS (1.0 / 1.1)"),
        ("🟠", "HTTP (unencrypted)"),
        ("🟠", "POP3 / IMAP / SNMP"),
        ("🟡", "SMTP without TLS"),
        ("🔴", "Plaintext Credentials"),
    ]
    for icon, name in threats:
        st.markdown(f"{icon} {name}")
    st.markdown("---")
    st.caption("⚠️ For authorized and educational use only.")


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

st.markdown('<div class="main-header">🔐 Cryptographic Protocol Analyzer</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Detect insecure protocols and weak cryptography in network traffic captures.</div>',
    unsafe_allow_html=True,
)

# ---- Controls ----
col_upload, col_demo = st.columns([3, 1])
with col_upload:
    uploaded_file = st.file_uploader(
        "Upload a .pcap or .pcapng file",
        type=["pcap", "pcapng"],
        label_visibility="collapsed",
    )
with col_demo:
    demo_clicked = st.button("▶ Run Demo Analysis", use_container_width=True)

# ---- State management ----
if "result" not in st.session_state:
    st.session_state.result = None
if "label" not in st.session_state:
    st.session_state.label = ""

# Trigger analysis
if demo_clicked:
    with st.spinner("Running demo analysis..."):
        st.session_state.result = run_demo_analysis()
        st.session_state.label = "demo"

if uploaded_file and not demo_clicked:
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=os.path.splitext(uploaded_file.name)[1],
    ) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    with st.spinner(f"Analyzing {uploaded_file.name}..."):
        st.session_state.result = analyze_pcap(tmp_path)
        st.session_state.label = uploaded_file.name
    os.unlink(tmp_path)

# ---- Render results ----
result = st.session_state.result

if result is None:
    # Landing state
    st.markdown("""
    <div class="demo-banner">
    ℹ️  <b>No file loaded.</b>  Upload a packet capture file above, or click <b>▶ Run Demo Analysis</b>
    to see the tool in action with a built-in sample dataset.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# Error handling
if result.get("error"):
    st.error(f"⚠️ Analysis Error\n\n{result['error']}")
    st.info("💡 **Tip:** Use **Run Demo Analysis** to explore the tool without a pcap file.")
    st.stop()

# Demo banner
if result.get("source") == "demo":
    st.markdown(
        '<div class="demo-banner">🎭 <b>Demo Mode</b> — Displaying built-in sample findings. '
        'Upload a real .pcap file for live analysis.</div>',
        unsafe_allow_html=True,
    )

summary = compute_summary(result)
findings = result.get("findings", [])

# ---- Summary metrics ----
st.markdown('<div class="section-title">📊 Summary</div>', unsafe_allow_html=True)
render_metric_cards(summary)

# ---- Chart + table columns ----
chart_col, table_col = st.columns([1, 2])

with chart_col:
    st.markdown('<div class="section-title">📈 Severity Breakdown</div>', unsafe_allow_html=True)
    render_severity_chart(result)

with table_col:
    st.markdown('<div class="section-title">📋 Findings Table</div>', unsafe_allow_html=True)
    df = findings_to_dataframe(findings)
    st.dataframe(df[["Severity", "Protocol", "Source IP", "Destination IP", "Dst Port", "Issue"]], 
                 use_container_width=True, height=280)

# ---- Download ----
df_full = findings_to_dataframe(findings)
csv_bytes = dataframe_to_csv_bytes(df_full)
st.download_button(
    label="⬇ Download Full CSV Report",
    data=csv_bytes,
    file_name=f"crypto_analysis_{summary['analyzed_at'].replace(' ', '_').replace(':', '')}.csv",
    mime="text/csv",
)

# ---- Detailed findings ----
st.markdown('<div class="section-title">🔍 Detailed Findings</div>', unsafe_allow_html=True)

if not findings:
    st.success("✅ No insecure protocols detected in this capture.")
else:
    # Severity filter
    severities = list(dict.fromkeys(f["severity"] for f in findings))
    selected = st.multiselect(
        "Filter by severity:",
        options=["Critical", "High", "Medium", "Low", "Info"],
        default=severities,
    )
    filtered = [f for f in findings if f.get("severity") in selected]
    st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
    render_finding_cards(filtered)

# ---- Footer ----
st.markdown("---")
st.caption(
    "🔒 **Ethical Notice:** This tool is intended for authorized network analysis and educational use only. "
    "Analyzing network traffic without permission may be illegal. Always obtain proper authorization."
)
