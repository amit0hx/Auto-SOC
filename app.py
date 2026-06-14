import streamlit as st
import pandas as pd
import joblib
import json
import time
import os
from datetime import datetime
from llm_engine import generate_ir_playbook, get_severity

# Live capture is optional — only available where scapy + Npcap are installed.
try:
    from live_ids import (capture_flows_live, classify_feats,
                          list_capture_ifaces, _origin, _rdns, FEATURE_COLS)
    LIVE_CAPTURE_AVAILABLE = True
except Exception:
    LIVE_CAPTURE_AVAILABLE = False

# ─── Page Config ───
st.set_page_config(
    page_title="Auto-SOC Dashboard",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS: Professional Dark SOC Theme (Datadog / Splunk-inspired) ───
st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

    /* Global */
    .stApp { background-color: #0f141b; color: #cbd5e1; }
    h1, h2, h3, h4 {
        font-family: 'Inter', sans-serif !important;
        color: #e8edf4 !important;
        font-weight: 600 !important;
    }
    p, span, div, li, label { font-family: 'Inter', sans-serif; }
    code, .stCode, pre { font-family: 'JetBrains Mono', monospace !important; }
    a { color: #60a5fa !important; }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: #1a222e;
        border: 1px solid #263041;
        border-radius: 10px;
        padding: 16px 18px;
    }
    [data-testid="stMetricLabel"] { color: #8b95a5 !important; font-size: 0.82rem; font-weight: 500; }
    [data-testid="stMetricValue"] { color: #e8edf4 !important; font-weight: 700; }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: #131a23;
        border-right: 1px solid #263041;
    }

    /* Buttons (primary = blue) */
    .stButton > button {
        background: #3b82f6;
        color: #ffffff;
        font-weight: 600;
        border: 1px solid #3b82f6;
        border-radius: 8px;
        padding: 0.55rem 1.1rem;
        transition: all 0.15s ease;
    }
    .stButton > button:hover {
        background: #2563eb;
        border-color: #2563eb;
        box-shadow: 0 4px 14px rgba(59, 130, 246, 0.25);
    }

    /* Alert boxes */
    .alert-critical {
        background: #1f1416;
        border: 1px solid #3f1f22;
        border-left: 4px solid #ef4444;
        padding: 14px 16px;
        border-radius: 8px;
        margin: 8px 0;
        color: #fca5a5;
    }
    .alert-normal {
        background: #10201a;
        border: 1px solid #1f3a2e;
        border-left: 4px solid #22c55e;
        padding: 14px 16px;
        border-radius: 8px;
        margin: 8px 0;
        color: #86efac;
    }
    .severity-badge {
        display: inline-block;
        padding: 3px 11px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        letter-spacing: 0.4px;
    }
    .sev-critical { background: #ef4444; color: #ffffff; }
    .sev-high { background: #f59e0b; color: #1a120a; }
    .sev-medium { background: #fbbf24; color: #1a1405; }
    .sev-info { background: #22c55e; color: #06210f; }

    /* Expander */
    [data-testid="stExpander"] {
        border: 1px solid #263041;
        border-radius: 10px;
        background: #151c26;
    }

    /* Divider */
    hr { border-color: #263041; }

    /* Tables */
    .stDataFrame { border: 1px solid #263041; border-radius: 8px; }
    [data-testid="stDataFrame"] thead tr th {
        background: #1a222e !important;
        color: #93c5fd !important;
        font-weight: 600;
    }

    /* Layout + hide default Streamlit chrome */
    .block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
    #MainMenu, footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent; }
    [data-testid="stToolbar"], [data-testid="stAppDeployButton"],
    .stDeployButton, [data-testid="stStatusWidget"] { display: none !important; }

    /* Hero banner */
    .hero {
        background: linear-gradient(135deg, #16202c 0%, #131a23 100%);
        border: 1px solid #263041;
        border-left: 4px solid #3b82f6;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 6px;
    }
    .hero-title { font-size: 1.9rem; font-weight: 700; color: #e8edf4; letter-spacing: 0.2px; }
    .hero-sub { color: #8b95a5; font-size: 0.95rem; margin-top: 3px; }
    .live-pill {
        display: inline-block; margin-top: 12px; padding: 3px 11px; border-radius: 6px;
        background: rgba(20, 184, 166, 0.12); border: 1px solid #14b8a6; color: #2dd4bf;
        font-size: 0.72rem; font-weight: 600; letter-spacing: 0.8px;
    }

    /* Section headings */
    h3 { border-bottom: 1px solid #263041; padding-bottom: 7px; font-size: 1.15rem !important; }

    /* Inputs */
    [data-testid="stSelectbox"] div[data-baseweb="select"] > div,
    [data-testid="stNumberInput"] input,
    [data-testid="stTextInput"] input {
        background-color: #151c26 !important;
        border-color: #263041 !important;
        color: #cbd5e1 !important;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-thumb { background: #263041; border-radius: 6px; }
    ::-webkit-scrollbar-track { background: #0f141b; }
    </style>
""", unsafe_allow_html=True)


# ─── Session State Init ───
if "attack_history" not in st.session_state:
    st.session_state.attack_history = []
if "total_packets" not in st.session_state:
    st.session_state.total_packets = 0
if "attack_count" not in st.session_state:
    st.session_state.attack_count = 0
if "normal_count" not in st.session_state:
    st.session_state.normal_count = 0


# ─── Load Model & Data ───
@st.cache_resource
def load_models():
    try:
        model = joblib.load("model.pkl")
        encoders = joblib.load("encoders.pkl")
        df = pd.read_csv("network_logs.csv")
        return model, encoders, df
    except Exception as e:
        return None, None, None

@st.cache_data
def load_metrics():
    try:
        with open("metrics.json", "r") as f:
            return json.load(f)
    except:
        return None

model, encoders, df = load_models()
metrics = load_metrics()


# ─── Sidebar: Model Intelligence Panel ───
with st.sidebar:
    st.markdown("## 🧠 Model Intelligence")
    st.markdown("---")

    if metrics:
        st.metric("Accuracy", f"{metrics['accuracy'] * 100:.1f}%")
        st.metric("CV Accuracy", f"{metrics['cv_accuracy_mean'] * 100:.1f}% ± {metrics['cv_accuracy_std'] * 100:.1f}%")
        st.metric("Train / Test Split", f"{metrics['train_size']} / {metrics['test_size']}")

        st.markdown("---")
        st.markdown("### 📊 Feature Importance")
        fi = metrics.get("feature_importance", {})
        if fi:
            fi_df = pd.DataFrame({
                "Feature": list(fi.keys()),
                "Importance": list(fi.values())
            }).sort_values("Importance", ascending=True)
            st.bar_chart(fi_df.set_index("Feature"), horizontal=True, color="#3b82f6")

        st.markdown("---")
        st.markdown("### 🎯 Per-Class Metrics")
        class_report = metrics.get("class_report", {})
        if class_report:
            cr_rows = []
            for cls, vals in class_report.items():
                if isinstance(vals, dict):
                    cr_rows.append({
                        "Class": cls,
                        "Precision": f"{vals.get('precision', 0):.2f}",
                        "Recall": f"{vals.get('recall', 0):.2f}",
                        "F1": f"{vals.get('f1-score', 0):.2f}",
                    })
            if cr_rows:
                st.dataframe(pd.DataFrame(cr_rows), hide_index=True, use_container_width=True)

        # Confusion Matrix Image
        if os.path.exists("confusion_matrix.png"):
            st.markdown("---")
            st.markdown("### 🔀 Confusion Matrix")
            st.image("confusion_matrix.png", use_container_width=True)
    else:
        st.warning("⚠️ No metrics found. Run `train_model.py` first.")

    st.markdown("---")
    st.markdown(
        "<div style='text-align:center; color:#5b6675; font-size:0.75rem;'>"
        "Auto-SOC v2.0 &nbsp;·&nbsp; by amit0hx"
        "</div>",
        unsafe_allow_html=True
    )


# ─── Main Dashboard ───
st.markdown(
    """
    <div class="hero">
        <div class="hero-title">🛡️ Auto-SOC</div>
        <div class="hero-sub">Intelligent Network Intrusion Detection &amp; Automated Incident Response</div>
        <span class="live-pill">● SOC ONLINE</span>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown("")

if model is None or encoders is None or df is None:
    st.error("❌ Model or dataset not loaded. Run these commands first:")
    st.code("python dataset_generator.py\npython train_model.py", language="bash")
    st.stop()


# ─── Live Stats Row ───
stat1, stat2, stat3, stat4 = st.columns(4)
with stat1:
    st.metric("📡 Packets Analyzed", st.session_state.total_packets)
with stat2:
    st.metric("🚨 Attacks Detected", st.session_state.attack_count)
with stat3:
    st.metric("✅ Normal Traffic", st.session_state.normal_count)
with stat4:
    detection_rate = (
        f"{(st.session_state.attack_count / st.session_state.total_packets * 100):.1f}%"
        if st.session_state.total_packets > 0 else "—"
    )
    st.metric("⚡ Detection Rate", detection_rate)

st.markdown("---")


# ─── Simulation Controls ───
def analyze_packet(sample_row):
    """Process a single packet through the ML pipeline and return results."""
    actual_label = sample_row['label'].values[0]
    features_for_display = sample_row.drop(columns=['label'])
    log_dict = features_for_display.to_dict(orient='records')[0]

    # Encode for prediction
    sample_proc = features_for_display.copy()
    for col, encoder_key in [('protocol_type', 'protocol_type'), ('service', 'service'), ('flag', 'flag')]:
        if col in sample_proc.columns and encoder_key in encoders:
            try:
                sample_proc[col] = encoders[encoder_key].transform(sample_proc[col])
            except ValueError:
                sample_proc[col] = 0  # Unknown label fallback

    prediction = model.predict(sample_proc)[0]
    severity = get_severity(prediction)

    result = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "prediction": prediction,
        "actual": actual_label,
        "severity": severity["level"],
        "severity_color": severity["color"],
        "log_data": log_dict,
        "correct": prediction == actual_label,
    }

    # Update session state counters
    st.session_state.total_packets += 1
    if prediction == "Normal":
        st.session_state.normal_count += 1
    else:
        st.session_state.attack_count += 1

    st.session_state.attack_history.insert(0, result)
    # Keep last 100 entries
    st.session_state.attack_history = st.session_state.attack_history[:100]

    return result


col_sim, col_batch = st.columns([2, 1])

with col_sim:
    simulate_one = st.button("🔍 Simulate Incoming Packet", use_container_width=True)

with col_batch:
    batch_size = st.selectbox("Batch Simulation", [10, 25, 50, 100], index=0, label_visibility="collapsed")
    simulate_batch = st.button(f"⚡ Simulate {batch_size} Packets", use_container_width=True)

st.markdown("---")

# ─── Single Packet Analysis ───
if simulate_one:
    sample = df.sample(1)
    result = analyze_packet(sample)

    col_packet, col_response = st.columns([1, 1])

    with col_packet:
        st.markdown("### 📡 Intercepted Packet")
        st.json(result["log_data"])

        if result["prediction"] == "Normal":
            st.markdown(
                f'<div class="alert-normal">✅ <b>Classification:</b> Normal Traffic</div>',
                unsafe_allow_html=True
            )
        else:
            sev_class = f"sev-{result['severity'].lower()}"
            st.markdown(
                f'<div class="alert-critical">'
                f'🚨 <b>ATTACK DETECTED:</b> {result["prediction"]}<br>'
                f'<span class="severity-badge {sev_class}">{result["severity"]}</span> '
                f'(CVSS: {get_severity(result["prediction"])["cvss_range"]})'
                f'</div>',
                unsafe_allow_html=True
            )

    with col_response:
        st.markdown("### 🤖 SOC Analyst Response")
        if result["prediction"] != "Normal":
            with st.spinner("Generating IR Playbook..."):
                time.sleep(0.5)
                playbook = generate_ir_playbook(result["log_data"], result["prediction"])
            st.markdown(playbook)
        else:
            st.info("✅ No action required — traffic classified as benign.")


# ─── Batch Packet Analysis ───
if simulate_batch:
    batch_results = []
    progress_bar = st.progress(0, text="Analyzing packets...")

    for i in range(batch_size):
        sample = df.sample(1)
        result = analyze_packet(sample)
        batch_results.append(result)
        progress_bar.progress((i + 1) / batch_size, text=f"Analyzed {i+1}/{batch_size} packets...")

    progress_bar.empty()
    st.success(f"✅ Batch analysis complete — {batch_size} packets processed.")

    # Batch summary
    batch_df = pd.DataFrame(batch_results)
    attack_types = batch_df[batch_df["prediction"] != "Normal"]["prediction"].value_counts()
    correct_count = batch_df["correct"].sum()

    b1, b2, b3 = st.columns(3)
    with b1:
        st.metric("Attacks in Batch", len(batch_df[batch_df["prediction"] != "Normal"]))
    with b2:
        st.metric("Correct Predictions", f"{correct_count}/{batch_size}")
    with b3:
        st.metric("Batch Accuracy", f"{(correct_count / batch_size * 100):.1f}%")

    if not attack_types.empty:
        st.markdown("#### Attack Distribution (This Batch)")
        st.bar_chart(attack_types, color="#ef4444")


# ─── Live Network Capture Section (real traffic → source IP) ───
st.markdown("---")
st.markdown("### 📡 Live Network Capture")
st.caption("Capture REAL packets from your network — unlike the synthetic simulator above, "
           "this shows the actual **source IP** of each connection and identifies attack origins.")

if not LIVE_CAPTURE_AVAILABLE:
    st.info("ℹ️ Live capture needs **scapy + Npcap** (install Wireshark). Falls back gracefully on systems without them.")
else:
    iface_opts = list_capture_ifaces()
    iface_labels = [f"{n}  ({ips})" if ips else n for n, ips in iface_opts]
    lc1, lc2, lc3 = st.columns([2, 1, 1])
    with lc1:
        sel = st.selectbox("Capture interface", range(len(iface_opts)),
                           format_func=lambda i: iface_labels[i], key="iface_sel")
    with lc2:
        cap_secs = st.slider("Duration (sec)", 5, 30, 12, key="cap_secs")
    with lc3:
        cap_max = st.number_input("Max packets", 50, 2000, 300, step=50, key="cap_max")

    _ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}

    if st.button("📡 Start Live Capture", use_container_width=True):
        iface_name = iface_opts[sel][0]
        try:
            with st.spinner(f"Capturing on '{iface_name}' for ~{cap_secs}s — generate some traffic now…"):
                feats = capture_flows_live(iface_name, int(cap_max), int(cap_secs))
                results = classify_feats(feats, model, encoders)
        except PermissionError:
            st.error("❌ Permission denied. Reinstall Npcap with admin-restriction OFF, or run as Administrator.")
            results = []
        except Exception as e:
            st.error(f"❌ Capture failed: {e}")
            results = []

        if not results:
            st.session_state.pop("lc", None)
            st.warning("No IP connections captured. Try again while browsing, or raise the duration.")
        else:
            attack_rows, all_rows, sources = [], [], {}
            for f, pred in results:
                sev = get_severity(pred)
                origin = _origin(f["_src"])
                row = {
                    "Source IP": f["_src"], "Target IP": f["_dst"],
                    "Service": f"{f['protocol_type']}/{f['service']}", "Flag": f["flag"],
                    "Prediction": f"{sev['color']} {pred}", "Severity": sev["level"],
                    "Origin": origin,
                }
                all_rows.append(row)
                if pred != "Normal":
                    attack_rows.append(row)
                    s = sources.setdefault(f["_src"], {"flows": 0, "types": set(),
                                                       "sev": "INFO", "origin": origin})
                    s["flows"] += 1
                    s["types"].add(pred)
                    if _ORDER.get(sev["level"], 0) > _ORDER.get(s["sev"], 0):
                        s["sev"] = sev["level"]

            # Build the ranked source table (resolve rDNS once, now).
            src_rows = []
            for ip, s in sorted(sources.items(), key=lambda kv: kv[1]["flows"], reverse=True):
                host = _rdns(ip) if s["origin"] == "EXTERNAL" else "—"
                src_rows.append({
                    "Source IP": ip, "Origin": s["origin"], "Severity": s["sev"],
                    "Attack Flows": s["flows"], "Attack Types": ", ".join(sorted(s["types"])),
                    "Reverse-DNS": host,
                })

            # Auto-generate an IR playbook for the #1 attacker's worst attack type.
            top_info, top_pb = None, None
            if sources:
                top_ip, top = max(sources.items(), key=lambda kv: kv[1]["flows"])
                worst = max(top["types"], key=lambda t: _ORDER.get(get_severity(t)["level"], 0))
                log = next(({c: f[c] for c in FEATURE_COLS}
                            for f, p in results if f["_src"] == top_ip and p == worst), None)
                if log is not None:
                    with st.spinner(f"Generating IR playbook for top attacker {top_ip}…"):
                        pb = generate_ir_playbook(log, worst)
                    top_pb = pb.replace("<SRC_IP>", top_ip)
                    top_info = {"ip": top_ip, "type": worst, "sev": top["sev"],
                                "origin": top["origin"], "flows": top["flows"]}

            st.session_state.lc = {
                "all_rows": all_rows, "n_attacks": len(attack_rows),
                "src_rows": src_rows, "top_info": top_info, "top_pb": top_pb,
            }

    # ── Render results (persisted, so playbook stays on reruns) ──
    lc = st.session_state.get("lc")
    if lc:
        m1, m2, m3 = st.columns(3)
        m1.metric("📡 Connections", len(lc["all_rows"]))
        m2.metric("🚨 Attacks", lc["n_attacks"])
        m3.metric("🌐 Unique Sources", len(lc["src_rows"]))

        st.markdown("#### 🎯 Attack Source Identification (who is attacking)")
        if lc["src_rows"]:
            st.dataframe(pd.DataFrame(lc["src_rows"]), use_container_width=True, hide_index=True)
            st.caption("Action: block/rate-limit EXTERNAL sources at the firewall; "
                       "investigate INTERNAL sources for possible compromise. "
                       "(rDNS resolving to a known service often signals a false positive.)")

            if lc["top_info"]:
                ti = lc["top_info"]
                sev_class = f"sev-{ti['sev'].lower()}"
                st.markdown(
                    f'<div class="alert-critical">🚨 <b>TOP ATTACKER IDENTIFIED:</b> '
                    f'<code>{ti["ip"]}</code> ({ti["origin"]})<br>'
                    f'<span class="severity-badge {sev_class}">{ti["sev"]}</span> '
                    f'{ti["type"]} — {ti["flows"]} attack flow(s) toward this host</div>',
                    unsafe_allow_html=True,
                )
                st.markdown("#### 🤖 Auto-Generated IR Playbook (for the top attacker)")
                st.markdown(lc["top_pb"])
        else:
            st.success("✅ No attacks detected — all captured traffic classified as Normal.")

        with st.expander(f"📋 All {len(lc['all_rows'])} captured connections"):
            st.dataframe(pd.DataFrame(lc["all_rows"]), use_container_width=True, hide_index=True)


# ─── Attack History Section ───
st.markdown("---")
st.markdown("### 📋 Attack History Log")

if st.session_state.attack_history:
    history_data = []
    for entry in st.session_state.attack_history:
        history_data.append({
            "Time": entry["timestamp"],
            "Prediction": f"{entry['severity_color']} {entry['prediction']}",
            "Actual": entry["actual"],
            "Severity": entry["severity"],
            "Protocol": entry["log_data"].get("protocol_type", "—"),
            "Service": entry["log_data"].get("service", "—"),
            "Flag": entry["log_data"].get("flag", "—"),
            "Match": "✅" if entry["correct"] else "❌",
        })
    history_df = pd.DataFrame(history_data)
    st.dataframe(history_df, use_container_width=True, hide_index=True)

    # Attack distribution pie chart from session history
    if st.session_state.attack_count > 0:
        st.markdown("#### 🥧 Session Attack Distribution")
        attack_entries = [e for e in st.session_state.attack_history if e["prediction"] != "Normal"]
        if attack_entries:
            attack_series = pd.Series([e["prediction"] for e in attack_entries]).value_counts()
            st.bar_chart(attack_series, color="#ef4444")

    # Clear history button
    if st.button("🗑️ Clear History"):
        st.session_state.attack_history = []
        st.session_state.total_packets = 0
        st.session_state.attack_count = 0
        st.session_state.normal_count = 0
        st.rerun()
else:
    st.info("No packets analyzed yet. Click 'Simulate Incoming Packet' to begin.")
