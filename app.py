import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import warnings
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cyber Security Threat Analytics Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

with open("style.css", encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# THEME / COLORS
# ─────────────────────────────────────────────────────────────────────────────
COLORS = {
    "primary": "#4f8ef7", "danger": "#ef4444", "warning": "#f59e0b",
    "success": "#10b981", "purple": "#8b5cf6", "teal": "#14b8a6",
    "muted": "#94a3b8", "text": "#e2e8f0",
}
PALETTE = [COLORS["primary"], COLORS["danger"], COLORS["warning"], COLORS["success"],
           COLORS["purple"], COLORS["teal"], "#f97316", "#ec4899", "#06b6d4", "#84cc16"]
CLASS_COLORS = {"anomaly": COLORS["danger"], "normal": COLORS["success"], "unlabeled": COLORS["muted"]}

def style_fig(fig, height=340):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLORS["text"], size=12),
        margin=dict(l=10, r=10, t=20, b=10), height=height,
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)),
    )
    fig.update_xaxes(gridcolor="rgba(255,255,255,0.05)", zeroline=False)
    fig.update_yaxes(gridcolor="rgba(255,255,255,0.05)", zeroline=False)
    return fig

# ─────────────────────────────────────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    return pd.read_csv("data/cleaned_data.csv", low_memory=False)

df_full = load_data()

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR — filters built ONLY from real dataset columns
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo">
        <span class="logo-icon">🛡️</span>
        <div>
            <div class="logo-title">CyberGuard</div>
            <div class="logo-sub">Analytics Platform</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    st.markdown('<div class="sidebar-section">NAVIGATION</div>', unsafe_allow_html=True)
    page = st.radio(
        "", options=["🏠  Dashboard", "🔴  Threat Analysis", "📡  Traffic Analysis", "📊  Data Quality"],
        label_visibility="collapsed",
    )
    page = page.split("  ")[1].strip()

    st.markdown("---")
    st.markdown('<div class="sidebar-section">FILTERS</div>', unsafe_allow_html=True)

    protocols = ["All"] + sorted(df_full["protocol_type"].dropna().unique().tolist())
    sel_protocol = st.selectbox("Protocol Type", protocols)

    services_all = ["All"] + sorted(df_full["service"].dropna().unique().tolist())
    sel_service = st.selectbox("Service Type", services_all)

    classes = ["All"] + sorted(df_full["class"].dropna().unique().tolist())
    sel_class = st.selectbox("Attack Type (class)", classes)

    threat_levels = ["All"] + sorted(df_full["threat_level"].dropna().unique().tolist())
    sel_threat = st.selectbox("Threat Level", threat_levels)

    traffic_cats = ["All"] + sorted(df_full["traffic_category"].dropna().unique().tolist())
    sel_traffic = st.selectbox("Traffic Category", traffic_cats)

    flags_all = ["All"] + sorted(df_full["flag"].dropna().unique().tolist())
    sel_flag = st.selectbox("Connection Flag", flags_all)

    st.markdown("---")
    st.markdown('<div class="sidebar-section">DATE FILTER</div>', unsafe_allow_html=True)
    st.caption("⚠️ Not available in dataset — NSL-KDD has no date/timestamp field.")

    st.markdown("---")
    st.markdown('<p class="sidebar-footer">⚡ Cyber Security Dashboard<br>Built with Streamlit & Plotly</p>',
                unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# APPLY FILTERS
# ─────────────────────────────────────────────────────────────────────────────
df = df_full.copy()
if sel_protocol != "All": df = df[df["protocol_type"] == sel_protocol]
if sel_service  != "All": df = df[df["service"] == sel_service]
if sel_class    != "All": df = df[df["class"] == sel_class]
if sel_threat   != "All": df = df[df["threat_level"] == sel_threat]
if sel_traffic  != "All": df = df[df["traffic_category"] == sel_traffic]
if sel_flag     != "All": df = df[df["flag"] == sel_flag]

if len(df) == 0:
    st.warning("⚠️ No data matches the current filters. Please adjust your selections.")
    st.stop()

# ─────────────────────────────────────────────────────────────────────────────
# KPI CALCULATIONS — all formulas from real columns
# ─────────────────────────────────────────────────────────────────────────────
total_records    = len(df)
total_attacks    = int((df["class"] == "anomaly").sum())
attack_pct       = round(total_attacks / total_records * 100, 2) if total_records else 0
total_traffic    = int(df["total_traffic"].sum())
high_risk_events = int((df["threat_level"] == "High").sum())
unique_services  = df["service"].nunique()
total_protocols  = df["protocol_type"].nunique()
avg_conn_dur     = round(df["duration"].mean(), 2)
most_freq_attack = (df.loc[df["class"] == "anomaly", "service"].value_counts().idxmax()
                     if total_attacks else "Not available")
completeness     = round((1 - df.isnull().sum().sum() / (df.shape[0] * df.shape[1])) * 100, 1)

# ─────────────────────────────────────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="top-header">
    <div class="header-left">
        <h1 class="dashboard-title">Cyber Security Threat Analytics Dashboard</h1>
        <p class="dashboard-sub">Network Intrusion Detection & Analysis — NSL-KDD Dataset</p>
    </div>
    <div class="header-right">
        <span class="status-dot"></span>
        <span class="status-text">System Active</span>
        &nbsp;&nbsp;|&nbsp;&nbsp;
        <span class="record-count">📋 {total_records:,} Records Loaded</span>
    </div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 1 — DASHBOARD (EXECUTIVE OVERVIEW)
# ═══════════════════════════════════════════════════════════════════════════
if page == "Dashboard":
    st.markdown('<h2 class="page-title">📊 Executive Overview</h2>', unsafe_allow_html=True)

    kpi_data = [
        ("Total Network Activities", f"{total_records:,}", "🔗", COLORS["primary"]),
        ("Total Threat Events", f"{total_attacks:,}", "🛡️", COLORS["danger"]),
        ("Threat Percentage", f"{attack_pct}%", "📈", COLORS["warning"]),
        ("High Risk Events", f"{high_risk_events:,}", "⚠️", COLORS["danger"]),
        ("Traffic Volume (bytes)", f"{total_traffic:,}", "📊", COLORS["primary"]),
        ("Unique Services", f"{unique_services}", "🔧", COLORS["purple"]),
    ]
    cols = st.columns(6)
    for i, (label, value, icon, color) in enumerate(kpi_data):
        with cols[i]:
            st.markdown(f"""
            <div class="kpi-card" style="border-top:3px solid {color};">
                <div class="kpi-header">
                    <span class="kpi-label">{label}</span>
                    <span class="kpi-icon" style="background:{color}22;">{icon}</span>
                </div>
                <div class="kpi-value" style="color:{color};">{value}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Row 1: Trend (by record_index) + Threat Distribution + Protocol Analysis
    col1, col2, col3 = st.columns([2, 1.2, 1.5])

    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Attack Trend Across Records (binned)</div>', unsafe_allow_html=True)
        st.caption("X-axis = record sequence bins (no real date field exists in dataset)")
        bins = min(40, max(10, total_records // 500))
        tmp = df.copy()
        tmp["bin"] = pd.cut(tmp["record_index"], bins=bins, labels=False)
        trend = tmp.groupby(["bin", "class"]).size().reset_index(name="count")
        fig = px.line(trend, x="bin", y="count", color="class", markers=True,
                      color_discrete_map=CLASS_COLORS)
        fig.update_traces(line=dict(width=2.5))
        style_fig(fig, 340)
        fig.update_xaxes(title="Record Bin")
        fig.update_yaxes(title="Events")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Threat Distribution</div>', unsafe_allow_html=True)
        td = df["threat_level"].value_counts().reset_index()
        td.columns = ["level", "count"]
        cmap = {"High": COLORS["danger"], "Medium": COLORS["warning"], "Low": COLORS["success"]}
        fig = px.pie(td, names="level", values="count", color="level",
                     color_discrete_map=cmap, hole=0.5)
        style_fig(fig, 340)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Protocol Analysis</div>', unsafe_allow_html=True)
        proto = df.groupby(["protocol_type", "class"]).size().reset_index(name="count")
        fig = px.bar(proto, x="protocol_type", y="count", color="class",
                     barmode="group", color_discrete_map=CLASS_COLORS)
        style_fig(fig, 340)
        fig.update_xaxes(title="Protocol")
        fig.update_yaxes(title="Count")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Row 2: Top Attack Categories + Heatmap (protocol x flag, real cols)
    col1, col2 = st.columns([1, 1.6])
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Top Attack Categories (by Service)</div>', unsafe_allow_html=True)
        top_attacks = df.loc[df["class"] == "anomaly", "service"].value_counts().head(8).reset_index()
        top_attacks.columns = ["service", "count"]
        if len(top_attacks):
            fig = px.bar(top_attacks, y="service", x="count", orientation="h",
                         color="count", color_continuous_scale=["#1e3a5f", "#4f8ef7", "#ef4444"])
            fig.update_coloraxes(showscale=False)
            style_fig(fig, 360)
            fig.update_yaxes(title="")
            fig.update_xaxes(title="Attack Count")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No anomaly records in current filter selection.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Network Activity Heatmap (Protocol × Service)</div>', unsafe_allow_html=True)
        top_svc = df["service"].value_counts().head(10).index
        heat = df[df["service"].isin(top_svc)].groupby(["protocol_type", "service"]).size().reset_index(name="count")
        heat_piv = heat.pivot_table(index="protocol_type", columns="service", values="count", fill_value=0)
        fig = px.imshow(heat_piv, color_continuous_scale=["#151724", "#1e3a5f", "#4f8ef7", "#ef4444"], aspect="auto")
        fig.update_coloraxes(colorbar=dict(thickness=10, len=0.8))
        style_fig(fig, 360)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    # Row 3: Source / Destination traffic, Connection duration, Service usage
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Source Bytes Distribution</div>', unsafe_allow_html=True)
        fig = px.histogram(df, x="src_bytes", nbins=25, color_discrete_sequence=[COLORS["primary"]])
        style_fig(fig, 250)
        fig.update_xaxes(title="src_bytes")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Destination Bytes Distribution</div>', unsafe_allow_html=True)
        fig = px.histogram(df, x="dst_bytes", nbins=25, color_discrete_sequence=[COLORS["warning"]])
        style_fig(fig, 250)
        fig.update_xaxes(title="dst_bytes")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Connection Duration Category</div>', unsafe_allow_html=True)
        cc = df["connection_category"].value_counts().reset_index()
        cc.columns = ["category", "count"]
        fig = px.bar(cc, x="category", y="count", color="count",
                     color_continuous_scale=["#1e3a5f", "#4f8ef7"])
        fig.update_coloraxes(showscale=False)
        style_fig(fig, 250)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col4:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Top Service Usage</div>', unsafe_allow_html=True)
        svc = df["service"].value_counts().head(6).reset_index()
        svc.columns = ["service", "count"]
        fig = px.bar(svc, x="service", y="count", color="count",
                     color_continuous_scale=["#1e3a5f", "#8b5cf6"])
        fig.update_coloraxes(showscale=False)
        style_fig(fig, 250)
        fig.update_xaxes(title="", tickangle=30)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="insights-box">
        <h4 class="insights-title">💡 Executive Insights</h4>
        <div class="insights-grid">
            <div class="insight-item"><span class="insight-icon">🔴</span>
                <span><strong>{attack_pct}%</strong> of network connections in the current filter are flagged as anomalies.</span></div>
            <div class="insight-item"><span class="insight-icon">⚠️</span>
                <span><strong>{high_risk_events:,}</strong> high-risk events detected based on derived ThreatLevel scoring.</span></div>
            <div class="insight-item"><span class="insight-icon">🔧</span>
                <span>Service <strong>'{most_freq_attack}'</strong> is the most frequently targeted service among anomaly records.</span></div>
            <div class="insight-item"><span class="insight-icon">📡</span>
                <span><strong>{unique_services}</strong> unique services observed across <strong>{total_protocols}</strong> protocol types.</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 2 — THREAT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
elif page == "Threat Analysis":
    st.markdown('<h2 class="page-title">🔴 Threat Analysis</h2>', unsafe_allow_html=True)

    k1, k2, k3, k4 = st.columns(4)
    mini = [
        ("Total Anomalies", f"{total_attacks:,}", COLORS["danger"], "🛡️"),
        ("High Risk Events", f"{high_risk_events:,}", COLORS["warning"], "⚠️"),
        ("Attack Rate", f"{attack_pct}%", COLORS["danger"], "📈"),
        ("Avg Risk Score", f"{round(df['risk_score'].mean(),1)}", COLORS["purple"], "🎯"),
    ]
    for col, (label, val, color, icon) in zip([k1, k2, k3, k4], mini):
        with col:
            st.markdown(f"""
            <div class="kpi-card" style="border-top:3px solid {color};">
                <div class="kpi-header">
                    <span class="kpi-label">{label}</span>
                    <span class="kpi-icon" style="background:{color}22;">{icon}</span>
                </div>
                <div class="kpi-value" style="color:{color};">{val}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns([1.2, 1])
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Attack Connections by Flag & Protocol</div>', unsafe_allow_html=True)
        atk = df[df["class"] == "anomaly"].groupby(["flag", "protocol_type"]).size().reset_index(name="count")
        if len(atk):
            fig = px.bar(atk, y="flag", x="count", color="protocol_type",
                         orientation="h", barmode="stack", color_discrete_sequence=PALETTE)
            style_fig(fig, 360)
            fig.update_yaxes(title="")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No anomaly records in current filter selection.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Attack Severity Distribution</div>', unsafe_allow_html=True)
        sev = df["attack_severity"].value_counts().reset_index()
        sev.columns = ["severity", "count"]
        sev_colors = {"Critical": COLORS["danger"], "High": "#f97316",
                      "Medium": COLORS["warning"], "Low": COLORS["success"]}
        fig = px.pie(sev, names="severity", values="count", color="severity",
                     color_discrete_map=sev_colors, hole=0.45)
        style_fig(fig, 360)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Threat Level by Protocol</div>', unsafe_allow_html=True)
        tl = df.groupby(["protocol_type", "threat_level"]).size().reset_index(name="count")
        fig = px.bar(tl, x="protocol_type", y="count", color="threat_level", barmode="group",
                     color_discrete_map={"High": COLORS["danger"], "Medium": COLORS["warning"], "Low": COLORS["success"]})
        style_fig(fig, 320)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Risk Score Distribution</div>', unsafe_allow_html=True)
        fig = px.histogram(df, x="risk_score", nbins=20, color_discrete_sequence=[COLORS["primary"]])
        fig.update_traces(marker_line_width=0.5, marker_line_color="#0f1523")
        style_fig(fig, 320)
        fig.update_xaxes(title="Risk Score (0-100)")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Most Targeted Services (Anomalies)</div>', unsafe_allow_html=True)
        rs = df.loc[df["class"] == "anomaly", "service"].value_counts().head(10).reset_index()
        rs.columns = ["service", "count"]
        if len(rs):
            fig = px.bar(rs, y="service", x="count", orientation="h", color_discrete_sequence=[COLORS["danger"]])
            style_fig(fig, 320)
            fig.update_yaxes(title="")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No anomaly records in current filter selection.")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="chart-card">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Attack Distribution Heatmap (Protocol × Flag)</div>', unsafe_allow_html=True)
    heat2 = df[df["class"] == "anomaly"].groupby(["protocol_type", "flag"]).size().reset_index(name="count")
    if len(heat2):
        heat2_piv = heat2.pivot_table(index="protocol_type", columns="flag", values="count", fill_value=0)
        fig = px.imshow(heat2_piv, color_continuous_scale=["#151724", "#1e3a5f", "#ef4444"],
                        text_auto=True, aspect="auto")
        style_fig(fig, 280)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No anomaly records in current filter selection.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="chart-card">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">serror_rate vs rerror_rate (Anomalies)</div>', unsafe_allow_html=True)
    st.caption("Error-rate fields are native dataset columns measuring SYN/REJ error frequency per connection")
    sample = df[df["class"] == "anomaly"]
    if len(sample):
        sample = sample.sample(min(2000, len(sample)), random_state=42)
        fig = px.scatter(sample, x="serror_rate", y="rerror_rate", color="protocol_type",
                         color_discrete_sequence=PALETTE, opacity=0.6)
        style_fig(fig, 300)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No anomaly records in current filter selection.")
    st.markdown('</div>', unsafe_allow_html=True)

    top_flag = df.loc[df["class"] == "anomaly", "flag"].value_counts().idxmax() if total_attacks else "N/A"
    top_sev = df["attack_severity"].value_counts().idxmax()
    st.markdown(f"""
    <div class="insights-box">
        <h4 class="insights-title">💡 Threat Analysis Insights</h4>
        <div class="insights-grid">
            <div class="insight-item"><span class="insight-icon">🔴</span>
                <span>Connection flag <strong>'{top_flag}'</strong> is most common among anomaly records.</span></div>
            <div class="insight-item"><span class="insight-icon">🎯</span>
                <span>Majority of records fall under <strong>'{top_sev}'</strong> attack severity.</span></div>
            <div class="insight-item"><span class="insight-icon">📊</span>
                <span>Average RiskScore across current selection: <strong>{round(df['risk_score'].mean(),1)}/100</strong>.</span></div>
            <div class="insight-item"><span class="insight-icon">🔧</span>
                <span>Service <strong>'{most_freq_attack}'</strong> shows the highest anomaly concentration.</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 3 — TRAFFIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
elif page == "Traffic Analysis":
    st.markdown('<h2 class="page-title">📡 Network Traffic Analysis</h2>', unsafe_allow_html=True)

    k1, k2, k3, k4, k5 = st.columns(5)
    tkpi = [
        ("Total Traffic (bytes)", f"{total_traffic:,}", COLORS["primary"], "📡"),
        ("Avg Src Bytes", f"{round(df['src_bytes'].mean()):,}", COLORS["teal"], "⬆️"),
        ("Avg Dst Bytes", f"{round(df['dst_bytes'].mean()):,}", COLORS["warning"], "⬇️"),
        ("Avg Duration (s)", f"{avg_conn_dur}", COLORS["purple"], "⏱️"),
        ("Total Connections", f"{total_records:,}", COLORS["success"], "🔗"),
    ]
    for col, (label, val, color, icon) in zip([k1, k2, k3, k4, k5], tkpi):
        with col:
            st.markdown(f"""
            <div class="kpi-card" style="border-top:3px solid {color};">
                <div class="kpi-header">
                    <span class="kpi-label">{label}</span>
                    <span class="kpi-icon" style="background:{color}22;">{icon}</span>
                </div>
                <div class="kpi-value" style="color:{color};">{val}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Traffic by Protocol</div>', unsafe_allow_html=True)
        tp = df.groupby("protocol_type")["total_traffic"].sum().reset_index()
        fig = px.pie(tp, names="protocol_type", values="total_traffic",
                     color_discrete_sequence=PALETTE, hole=0.4)
        style_fig(fig, 320)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Top 10 Services by Traffic</div>', unsafe_allow_html=True)
        svc_tr = df.groupby("service")["total_traffic"].sum().nlargest(10).reset_index()
        fig = px.bar(svc_tr, y="service", x="total_traffic", orientation="h",
                     color="total_traffic", color_continuous_scale=["#1e3a5f", "#4f8ef7"])
        fig.update_coloraxes(showscale=False)
        style_fig(fig, 320)
        fig.update_yaxes(title="")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Traffic Category Distribution</div>', unsafe_allow_html=True)
        tc = df["traffic_category"].value_counts().reset_index()
        tc.columns = ["category", "count"]
        fig = px.pie(tc, names="category", values="count",
                     color_discrete_sequence=[COLORS["success"], COLORS["warning"], COLORS["danger"]], hole=0.4)
        style_fig(fig, 320)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([1.5, 1])
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Source vs Destination Bytes (Scatter Sample)</div>', unsafe_allow_html=True)
        sample = df.sample(min(2500, len(df)), random_state=42)
        fig = px.scatter(sample, x="src_bytes", y="dst_bytes", color="class",
                         color_discrete_map=CLASS_COLORS, opacity=0.5)
        style_fig(fig, 340)
        fig.update_xaxes(title="src_bytes")
        fig.update_yaxes(title="dst_bytes")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Connection Duration Distribution</div>', unsafe_allow_html=True)
        dur_data = df[df["duration"] > 0]
        if len(dur_data):
            fig = px.histogram(dur_data, x="duration", nbins=30, color_discrete_sequence=[COLORS["purple"]])
            fig.update_traces(marker_line_width=0.5)
            style_fig(fig, 340)
            fig.update_xaxes(title="Duration (s)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("All connections in current filter have 0 duration.")
        st.markdown('</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Traffic by Connection Category</div>', unsafe_allow_html=True)
        conn_tr = df.groupby("connection_category")["total_traffic"].sum().reset_index()
        fig = px.bar(conn_tr, x="connection_category", y="total_traffic", color_discrete_sequence=[COLORS["teal"]])
        style_fig(fig, 280)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Same-Service Rate Distribution</div>', unsafe_allow_html=True)
        st.caption("same_srv_rate — native dataset column: % connections to same service")
        fig = px.histogram(df, x="same_srv_rate", nbins=20, color_discrete_sequence=[COLORS["primary"]])
        style_fig(fig, 280)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Connection Count vs Service Count</div>', unsafe_allow_html=True)
        st.caption("count vs srv_count — native dataset columns")
        sample2 = df.sample(min(1500, len(df)), random_state=1)
        fig = px.scatter(sample2, x="count", y="srv_count", color="class",
                         color_discrete_map=CLASS_COLORS, opacity=0.5)
        style_fig(fig, 280)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    top_proto = df.groupby("protocol_type")["total_traffic"].sum().idxmax()
    top_svc_tr = df.groupby("service")["total_traffic"].sum().idxmax()
    st.markdown(f"""
    <div class="insights-box">
        <h4 class="insights-title">💡 Traffic Analysis Insights</h4>
        <div class="insights-grid">
            <div class="insight-item"><span class="insight-icon">📡</span>
                <span>Protocol <strong>'{top_proto.upper()}'</strong> generates the highest total traffic volume.</span></div>
            <div class="insight-item"><span class="insight-icon">🔧</span>
                <span>Service <strong>'{top_svc_tr}'</strong> accounts for the largest share of data transfer.</span></div>
            <div class="insight-item"><span class="insight-icon">📊</span>
                <span>Average connection duration is <strong>{avg_conn_dur}s</strong> in current selection.</span></div>
            <div class="insight-item"><span class="insight-icon">⬆️</span>
                <span>Total traffic volume of <strong>{total_traffic:,} bytes</strong> across {total_records:,} connections.</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# PAGE 4 — DATA QUALITY
# ═══════════════════════════════════════════════════════════════════════════
elif page == "Data Quality":
    st.markdown('<h2 class="page-title">📊 Data Quality Dashboard</h2>', unsafe_allow_html=True)

    import json
    try:
        with open("data/quality_log.json", encoding="utf-8") as f:
            qlog = json.load(f)
    except FileNotFoundError:
        qlog = {"duplicates_removed": "N/A", "missing_values_found": 0,
                "total_records_before": "N/A", "total_records_after": total_records}

    k1, k2, k3, k4, k5 = st.columns(5)
    dq = [
        ("Total Records", f"{total_records:,}", COLORS["primary"], "📋"),
        ("Missing Values", f"{df.isnull().sum().sum():,}", COLORS["success"], "✅"),
        ("Duplicates Removed", f"{qlog['duplicates_removed']}", COLORS["warning"], "🗑️"),
        ("Completeness Score", f"{completeness}%", COLORS["success"], "📊"),
        ("Engineered Features", "7", COLORS["purple"], "⚙️"),
    ]
    for col, (label, val, color, icon) in zip([k1, k2, k3, k4, k5], dq):
        with col:
            st.markdown(f"""
            <div class="kpi-card" style="border-top:3px solid {color};">
                <div class="kpi-header">
                    <span class="kpi-label">{label}</span>
                    <span class="kpi-icon" style="background:{color}22;">{icon}</span>
                </div>
                <div class="kpi-value" style="color:{color};">{val}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Missing Values per Column</div>', unsafe_allow_html=True)
        miss = df.isnull().sum().reset_index()
        miss.columns = ["column", "missing"]
        miss = miss[miss["missing"] > 0]
        if len(miss) == 0:
            st.markdown("""
            <div style='text-align:center;padding:40px;color:#10b981;'>
                <div style='font-size:48px;'>✅</div>
                <div style='font-size:16px;margin-top:10px;'>Dataset is 100% Complete — No Missing Values</div>
            </div>""", unsafe_allow_html=True)
        else:
            fig = px.bar(miss, x="column", y="missing", color_discrete_sequence=[COLORS["danger"]])
            style_fig(fig, 320)
            st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Outlier Counts by Column (IQR×3 method)</div>', unsafe_allow_html=True)
        if "outlier_counts_by_column" in qlog:
            out_df = pd.DataFrame(list(qlog["outlier_counts_by_column"].items()),
                                  columns=["column", "outliers"])
            out_df = out_df[out_df["outliers"] > 0].sort_values("outliers", ascending=False).head(12)
            if len(out_df):
                fig = px.bar(out_df, x="column", y="outliers", color_discrete_sequence=[COLORS["warning"]])
                style_fig(fig, 320)
                fig.update_xaxes(tickangle=45)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No significant outliers detected.")
        else:
            st.info("Outlier log not available.")
        st.markdown('</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Class Balance (Train + Test)</div>', unsafe_allow_html=True)
        cd = df["class"].value_counts().reset_index()
        cd.columns = ["class", "count"]
        fig = px.bar(cd, x="class", y="count", color="class",
                     color_discrete_map=CLASS_COLORS, text="count")
        fig.update_traces(textposition="outside")
        style_fig(fig, 320)
        st.plotly_chart(fig, use_container_width=True)
        st.caption("'unlabeled' = records from Test_data.csv, which has no class column in source.")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Numerical Feature Boxplot (Outlier View)</div>', unsafe_allow_html=True)
        box_cols = ["src_bytes", "dst_bytes", "duration"]
        fig = go.Figure()
        for i, c in enumerate(box_cols):
            fig.add_trace(go.Box(y=df[c], name=c, marker_color=PALETTE[i], boxpoints=False))
        style_fig(fig, 320)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Data Cleaning Summary</div>', unsafe_allow_html=True)
        clean_df = pd.DataFrame({
            "Step": ["Records Before", "Duplicates Removed", "Records After",
                     "Missing Values", "Outliers Capped (IQR×3)", "Features Engineered"],
            "Value": [f"{qlog.get('total_records_before','N/A')}",
                      f"{qlog['duplicates_removed']}",
                      f"{qlog.get('total_records_after', total_records)}",
                      f"{qlog['missing_values_found']}",
                      "Yes — capped, not removed",
                      "7 (total_traffic, traffic_category, threat_level, connection_category, risk_score, attack_severity, record_index)"],
        })
        st.dataframe(clean_df, hide_index=True, use_container_width=True, height=280)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="chart-card">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Feature Correlation Matrix (Native Numerical Columns)</div>', unsafe_allow_html=True)
    corr_cols = ["duration", "src_bytes", "dst_bytes", "count", "srv_count",
                 "serror_rate", "rerror_rate", "same_srv_rate", "num_failed_logins", "risk_score"]
    corr_mat = df[corr_cols].corr()
    fig = px.imshow(corr_mat, color_continuous_scale="RdBu_r", text_auto=".2f", aspect="auto", zmin=-1, zmax=1)
    style_fig(fig, 380)
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="insights-box">
        <h4 class="insights-title">💡 Data Quality Insights</h4>
        <div class="insights-grid">
            <div class="insight-item"><span class="insight-icon">✅</span>
                <span>Dataset completeness score: <strong>{completeness}%</strong> — source NSL-KDD data has zero missing values.</span></div>
            <div class="insight-item"><span class="insight-icon">🗑️</span>
                <span><strong>{qlog['duplicates_removed']} duplicate records</strong> were removed during cleaning.</span></div>
            <div class="insight-item"><span class="insight-icon">⚙️</span>
                <span><strong>7 engineered features</strong> were derived strictly from existing dataset columns.</span></div>
            <div class="insight-item"><span class="insight-icon">📊</span>
                <span>Outliers were <strong>capped (not deleted)</strong> using the IQR × 3 method to preserve record count.</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)
