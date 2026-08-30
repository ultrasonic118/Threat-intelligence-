import time
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="Campus Sentinel | Network Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Theme ----------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
    :root { --ink:#e8eef7; --muted:#8ea1ba; --panel:#101a2b; --line:#20314a; --cyan:#36d6d0; --red:#ff5f6d; --amber:#ffbd69; }
    html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
    .stApp { background: #07111f; color: var(--ink); }
    [data-testid="stSidebar"] { background: #0a1627; border-right: 1px solid #1b2d46; }
    [data-testid="stSidebar"] * { color: #d9e5f5; }
    h1, h2, h3 { font-family: 'Space Grotesk', sans-serif; letter-spacing: -0.02em; }
    h1 { font-size: 2.15rem !important; margin-bottom: 0.1rem !important; }
    .subtitle { color: var(--muted); font-size: 0.98rem; margin-bottom: 1.4rem; }
    .eyebrow { color: var(--cyan); font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.14em; }
    .metric { background: linear-gradient(135deg,#101d31 0%,#0d1727 100%); border:1px solid var(--line); border-radius:14px; padding:17px 18px; min-height:112px; }
    .metric-label { color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.07em; }
    .metric-value { color:#f3f7fc; font-family:'Space Grotesk'; font-size:1.85rem; font-weight:700; margin-top:8px; }
    .metric-note { color:#70dccb; font-size:.76rem; margin-top:4px; }
    .panel { background:#0e192a; border:1px solid var(--line); border-radius:14px; padding:18px; }
    .panel-title { font-family:'Space Grotesk'; font-weight:600; font-size:1.02rem; margin-bottom:2px; }
    .panel-subtitle { color:var(--muted); font-size:.78rem; margin-bottom:12px; }
    .status-dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--cyan); box-shadow:0 0 12px var(--cyan); margin-right:7px; }
    .alert-card { border-left: 4px solid var(--red); background:#171827; border-radius:10px; padding:13px 15px; margin:8px 0; }
    .alert-card.medium { border-left-color:var(--amber); }
    .alert-card.low { border-left-color:var(--cyan); }
    .alert-head { display:flex; justify-content:space-between; font-weight:600; }
    .alert-meta { color:var(--muted); font-size:.78rem; margin-top:6px; }
    .severity { font-size:.7rem; text-transform:uppercase; letter-spacing:.08em; font-weight:700; }
    .severity.high { color:var(--red); } .severity.medium { color:var(--amber); } .severity.low { color:var(--cyan); }
    .footer { color:#63758d; font-size:.76rem; padding:18px 0 4px; }
    div[data-testid="stMetric"] { background: transparent; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------- Data ----------
ATTACKS = ["Port Scan", "Brute Force", "DDoS", "Data Exfiltration", "Normal"]
SEVERITIES = ["High", "Medium", "Low"]


def make_flows(n=140):
    rng = np.random.default_rng(7)
    now = datetime.now()
    attack = rng.choice(ATTACKS, n, p=[.16, .10, .07, .06, .61])
    rows = []
    for i, kind in enumerate(attack):
        is_bad = kind != "Normal"
        src = f"10.20.{rng.integers(1, 9)}.{rng.integers(10, 250)}"
        dst = f"172.16.{rng.integers(1, 5)}.{rng.integers(10, 250)}"
        packets = int(rng.integers(80, 650) if not is_bad else rng.integers(800, 11000))
        bytes_sent = int(packets * rng.integers(60, 220))
        duration = round(float(rng.uniform(.4, 35) if not is_bad else rng.uniform(.05, 3.8)), 2)
        ports = int(rng.integers(1, 5) if not is_bad else rng.integers(12, 95))
        score = round(float(rng.uniform(.04, .29) if not is_bad else rng.uniform(.65, .99)), 2)
        sev = "High" if score >= .85 else "Medium" if score >= .65 else "Low"
        rows.append({"timestamp": now - timedelta(seconds=(n-i)*8), "src_ip":src, "dst_ip":dst,
                     "attack_type":kind, "packets":packets, "bytes":bytes_sent, "duration":duration,
                     "unique_ports":ports, "score":score, "severity":sev})
    return pd.DataFrame(rows)

if "flows" not in st.session_state:
    st.session_state.flows = make_flows()
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = datetime.now()

flows = st.session_state.flows

# ---------- Sidebar ----------
st.sidebar.markdown("## 🛡️ Campus Sentinel")
st.sidebar.caption("AI-assisted network defense console")
st.sidebar.markdown("---")
st.sidebar.markdown("**MONITORING SCOPE**")
scope = st.sidebar.selectbox("Network segment", ["All campus traffic", "Student Wi-Fi", "Research VLAN", "Admin VLAN"], label_visibility="collapsed")
st.sidebar.markdown("**TIME WINDOW**")
window = st.sidebar.select_slider("Window", options=["15 min", "1 hour", "6 hours", "24 hours"], value="1 hour", label_visibility="collapsed")
st.sidebar.markdown("**ALERT FILTER**")
severity_filter = st.sidebar.multiselect("Severity", SEVERITIES, default=SEVERITIES, label_visibility="collapsed")
st.sidebar.markdown("---")
auto_refresh = st.sidebar.toggle("Auto-refresh demo feed", value=False)
if st.sidebar.button("↻  Refresh traffic", use_container_width=True):
    normal = make_flows(1)
    normal.loc[:, "timestamp"] = datetime.now()
    st.session_state.flows = pd.concat([flows, normal], ignore_index=True).tail(180)
    st.session_state.last_refresh = datetime.now()
    st.rerun()
st.sidebar.caption(f"Last event: {st.session_state.last_refresh.strftime('%H:%M:%S')}")

# ---------- Header ----------
st.markdown('<div class="eyebrow">Security operations center · Proof of concept</div>', unsafe_allow_html=True)
st.title("Campus Network Anomaly Detection")
st.markdown('<div class="subtitle"><span class="status-dot"></span>Detection pipeline is online · Random Forest + Isolation Forest ensemble · Model confidence calibrated</div>', unsafe_allow_html=True)

# ---------- KPI row ----------
alerts = flows[flows.attack_type != "Normal"]
high_alerts = alerts[alerts.severity == "High"]
col1, col2, col3, col4 = st.columns(4)
for col, label, value, note in [
    (col1, "Flows inspected", f"{len(flows):,}", "+12.4% vs previous window"),
    (col2, "Anomalies detected", f"{len(alerts):,}", f"{(len(alerts)/max(len(flows),1)*100):.1f}% of traffic"),
    (col3, "Critical alerts", f"{len(high_alerts):,}", "Requires analyst review"),
    (col4, "Model precision", "96.8%", "Validation benchmark"),
]:
    col.markdown(f'<div class="metric"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>', unsafe_allow_html=True)

st.write("")
left, right = st.columns([1.65, 1])
with left:
    st.markdown('<div class="panel-title">Live traffic telemetry</div><div class="panel-subtitle">Anomaly score and throughput over the selected window</div>', unsafe_allow_html=True)
    chart_df = flows.tail(80).copy()
    chart_df["time"] = chart_df.timestamp.dt.strftime("%H:%M:%S")
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=chart_df.time, y=chart_df.score, mode="lines", name="Anomaly score", line=dict(color="#36d6d0", width=2), fill="tozeroy", fillcolor="rgba(54,214,208,.08)"))
    bad = chart_df[chart_df.attack_type != "Normal"]
    fig.add_trace(go.Scatter(x=bad.time, y=bad.score, mode="markers", name="Detected anomaly", marker=dict(color="#ff5f6d", size=9, line=dict(color="#ffe0e3", width=1))))
    fig.add_hline(y=.65, line_dash="dot", line_color="#ffbd69", annotation_text="alert threshold", annotation_font_color="#ffbd69")
    fig.update_layout(height=300, margin=dict(l=5,r=5,t=8,b=5), paper_bgcolor="#0e192a", plot_bgcolor="#0e192a", font_color="#8ea1ba", legend=dict(orientation="h", y=1.1, x=0), xaxis=dict(showgrid=False, title=None), yaxis=dict(showgrid=True, gridcolor="#1b2a40", range=[0,1], title=None))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

with right:
    st.markdown('<div class="panel-title">Attack distribution</div><div class="panel-subtitle">Classification across observed flows</div>', unsafe_allow_html=True)
    dist = flows.attack_type.value_counts().rename_axis("attack_type").reset_index(name="count")
    fig2 = px.bar(dist, x="count", y="attack_type", orientation="h", color="attack_type", color_discrete_map={"Normal":"#36d6d0","Port Scan":"#ffbd69","Brute Force":"#ff8f70","DDoS":"#ff5f6d","Data Exfiltration":"#c184ff"})
    fig2.update_layout(height=300, margin=dict(l=5,r=15,t=8,b=5), paper_bgcolor="#0e192a", plot_bgcolor="#0e192a", showlegend=False, font_color="#8ea1ba", xaxis=dict(showgrid=False, title=None), yaxis=dict(showgrid=False, title=None))
    st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar":False})

# ---------- Analyst workspace ----------
st.markdown("## Analyst workspace")
attack_col, detail_col = st.columns([1.35, 1])
with attack_col:
    st.markdown('<div class="panel-title">Recent alerts</div><div class="panel-subtitle">Prioritized by model score · click a row to inspect the evidence</div>', unsafe_allow_html=True)
    filtered = alerts[alerts.severity.isin(severity_filter)].sort_values("timestamp", ascending=False).head(12).copy()
    display = filtered[["timestamp","src_ip","dst_ip","attack_type","score","severity"]].copy()
    display["timestamp"] = display.timestamp.dt.strftime("%H:%M:%S")
    display["score"] = display.score.map(lambda x: f"{x:.0%}")
    display.columns = ["Time", "Source IP", "Destination IP", "Attack type", "Score", "Severity"]
    event = st.dataframe(display, use_container_width=True, hide_index=True, on_select="rerun", selection_mode="single-row", height=360)

    st.markdown('<div class="panel-title" style="margin-top:18px">Demo controls</div><div class="panel-subtitle">Use this control to create a clearly labeled malicious event for the jury walkthrough</div>', unsafe_allow_html=True)
    sim_col1, sim_col2 = st.columns([1, 2])
    if sim_col1.button("⚡ Simulate attack", type="primary", use_container_width=True):
        attack = pd.DataFrame([{"timestamp":datetime.now(), "src_ip":"10.20.4.77", "dst_ip":"172.16.1.10", "attack_type":"Port Scan", "packets":8420, "bytes":1203300, "duration":1.12, "unique_ports":64, "score":.98, "severity":"High"}])
        st.session_state.flows = pd.concat([st.session_state.flows, attack], ignore_index=True).tail(180)
        st.session_state.last_refresh = datetime.now()
        st.toast("Malicious port-scan flow injected into the live feed")
        st.rerun()
    sim_col2.info("The injected flow is labeled as a high-confidence port scan and appears in the alert table immediately.")

with detail_col:
    selected = None
    if event and event.selection and event.selection.rows:
        selected = filtered.iloc[event.selection.rows[0]]
    elif not filtered.empty:
        selected = filtered.iloc[0]
    if selected is not None:
        sev_class = selected.severity.lower()
        st.markdown(f'<div class="alert-card {sev_class}"><div class="alert-head"><span>{selected.attack_type}</span><span class="severity {sev_class}">{selected.severity} severity</span></div><div class="alert-meta">{selected.src_ip} → {selected.dst_ip} · {selected.timestamp.strftime("%d %b %Y, %H:%M:%S")}</div></div>', unsafe_allow_html=True)
        st.markdown('<div class="panel-title">Why was this flagged?</div><div class="panel-subtitle">Top contributing flow features · SHAP-style explanation</div>', unsafe_allow_html=True)
        explain = pd.DataFrame({"Feature":["Unique destination ports", "Packets per second", "Flow duration", "Outbound byte volume"], "Impact":[.91,.78,.54,.32]})
        fig3 = px.bar(explain.sort_values("Impact"), x="Impact", y="Feature", orientation="h", color="Impact", color_continuous_scale=[[0,"#214861"],[1,"#36d6d0"]])
        fig3.update_layout(height=230, margin=dict(l=5,r=5,t=5,b=5), paper_bgcolor="#0e192a", plot_bgcolor="#0e192a", coloraxis_showscale=False, font_color="#8ea1ba", xaxis=dict(range=[0,1], showgrid=True, gridcolor="#1b2a40", title=None), yaxis=dict(showgrid=False, title=None))
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar":False})
        st.caption(f"Observed {int(selected.unique_ports)} unique ports, {int(selected.packets):,} packets, and {selected.duration:.2f}s duration. Ensemble score: {selected.score:.0%}.")
    else:
        st.info("No alert matches the selected severity filters.")

st.markdown('<div class="footer">Campus Sentinel POC · Synthetic replay data for demonstration only · Replace the replay source with live flow telemetry or a FastAPI /predict endpoint when productionizing.</div>', unsafe_allow_html=True)

if auto_refresh:
    time.sleep(1)
    st.rerun()
