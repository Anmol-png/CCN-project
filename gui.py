import streamlit as st
import pandas as pd
import os
import matplotlib.pyplot as plt
import psutil
import time

# --- 🌙 Dark Theme Settings ---
st.set_page_config(page_title="System Monitor Dashboard", layout="wide")

# --- 🎨 Custom Professional Dark Theme ---
st.markdown("""
    <style>
    /* === Main Page Styling === */
    .main {
        background-color: #0e1117;
        color: #ffffff;
    }

    /* === Sidebar Background === */
    [data-testid="stSidebar"] {
        background-color: #111827 !important;
    }

    /* === Sidebar Title === */
    [data-testid="stSidebar"] h1 {
        color: #00b4d8 !important;
        font-size: 24px !important;
        font-weight: 700 !important;
        text-align: center;
        margin-bottom: 20px;
    }

    /* === Sidebar Radio Buttons (Navigation Text) === */
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        font-size: 18px !important;
        color: #00ffff !important;
        font-weight: 600 !important;
        margin-bottom: 10px !important;
        padding: 6px 10px;
        border-radius: 6px;
        transition: all 0.3s ease-in-out;
    }

    /* Hover effect for sidebar text */
    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #1e293b !important;
        color: #ffffff !important;
    }

    /* Selected option (active page) */
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-testid="stMarkdownContainer"] {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Headings */
    h1, h2, h3, h4 {
        color: #00b4d8 !important;
    }

    /* DataFrame Background */
    .stDataFrame {
        background-color: #111 !important;
    }

    /* Alert text */
    .stAlert {
        font-size: 16px !important;
    }

    /* Charts and plots */
    .stPlotlyChart, .stAltairChart, .stVegaLiteChart, .stDeckGlChart {
        background-color: #111827 !important;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# --- 🧭 Sidebar Navigation ---
st.sidebar.title("System Dashboard")
page = st.sidebar.radio("Navigate", [
    "Real-Time Monitor",
    "CSV Log Viewer",
    "Historical Graphs",
    "Comparison Mode",
    "About"
])

# --- 🔍 Helper function to read system stats ---
def get_syscalls_and_context_switches():
    syscalls = ctxt = 0
    with open("/proc/stat", "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith("processes "):
            syscalls = int(line.split()[1])
        elif line.startswith("ctxt "):
            ctxt = int(line.split()[1])
    return syscalls, ctxt


# --- PAGE 1: Real-Time Monitor ---
if page == "Real-Time Monitor":
    st.title("Real-Time System and Energy Dashboard")
    st.markdown("""
    **How it works:**
    - Run your terminal monitor → `sudo python3 energy.py`
    - This dashboard auto-refreshes every few seconds when new data is logged.
    """)

    log_file = "system_monitor_log.csv"

    if not os.path.exists(log_file):
        st.warning("Log file not found yet. Please run `sudo python3 energy.py` in another terminal.")
        st.stop()

    placeholder = st.empty()

    # Auto-refresh loop
    while True:
        try:
            if os.path.exists(log_file):
                df = pd.read_csv(log_file)
                if not df.empty:
                    df = df.tail(100)  # Keep recent samples
                    st.success(f"Last updated: {df.iloc[-1, 0]} ({len(df)} samples)")
                    st.line_chart(df.set_index(df.columns[0]))
            else:
                st.warning("Waiting for log file...")

            time.sleep(2)
            st.rerun()
        except Exception as e:
            st.error(f"Error reading log: {e}")
            time.sleep(2)


# --- PAGE 2: CSV Log Viewer ---
elif page == "CSV Log Viewer":
    st.title("System Log Viewer")

    log_path = "system_monitor_log.csv"
    df = None

    if os.path.exists(log_path):
        st.success(f"Automatically loaded: {log_path}")
        df = pd.read_csv(log_path)
    else:
        st.warning("Log file not found. Please upload a CSV manually.")
        uploaded = st.file_uploader("Upload your system_monitor_log.csv file", type=["csv"])
        if uploaded:
            df = pd.read_csv(uploaded)
            st.success("File uploaded successfully!")

    if df is not None:
        st.dataframe(df, use_container_width=True)
        if st.button("Show Basic Stats"):
            st.write(df.describe())


# --- PAGE 3: Historical Graphs ---
elif page == "Historical Graphs":
    st.title("Historical Data Visualization")

    log_path = "system_monitor_log.csv"
    if os.path.exists(log_path):
        df = pd.read_csv(log_path)
        st.success(f"Loaded: {log_path}")

        numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns.tolist()
        if numeric_cols:
            selected_metric = st.selectbox("Select a metric to visualize:", numeric_cols)

            fig, ax = plt.subplots(figsize=(10, 5))
            y = df[selected_metric]
            x = range(len(y))

            ax.plot(x, y, color="#00b4d8", linewidth=2, label=selected_metric)
            max_idx = y.idxmax()
            min_idx = y.idxmin()
            ax.scatter(max_idx, y[max_idx], color='red', s=100, label=f"Max: {y[max_idx]:.2f}")
            ax.scatter(min_idx, y[min_idx], color='lime', s=100, label=f"Min: {y[min_idx]:.2f}")

            ax.set_xlabel("Time / Index", color='white', fontsize=12)
            ax.set_ylabel(selected_metric, color='white', fontsize=12)
            ax.set_title(f"{selected_metric} Trend with Highlighted Extremes", color='#00b4d8', fontsize=16)

            ax.set_facecolor('#111827')
            fig.patch.set_facecolor('#0e1117')
            ax.tick_params(colors='white')

            ax.legend(facecolor="#111827", labelcolor='white')
            st.pyplot(fig)

            st.markdown(f"""
                **Metric:** `{selected_metric}`  
                **Max Value:** {y[max_idx]:.2f} (at index {max_idx})  
                **Min Value:** {y[min_idx]:.2f} (at index {min_idx})  
            """)
        else:
            st.warning("No numeric columns found in CSV.")
    else:
        st.warning("No system_monitor_log.csv found. Please upload in the Log Viewer section.")


# --- PAGE 4: Comparison Mode (Direct Files, Metric Select) ---
elif page == "Comparison Mode":
    st.title("Compare eBPF vs Baseline Models")
    st.write("Automatically loading existing CSV files for comparison.")

    # --- Load files directly ---
    ebpf_file = "system_monitor_log.csv"
    baseline_file = "baseline_monitor_log.csv"

    if os.path.exists(ebpf_file) and os.path.exists(baseline_file):
        df_ebpf = pd.read_csv(ebpf_file)
        df_base = pd.read_csv(baseline_file)

        # Strip column names to avoid KeyError due to extra spaces
        df_ebpf.columns = df_ebpf.columns.str.strip()
        df_base.columns = df_base.columns.str.strip()

        st.success("Both CSV files loaded successfully!")

        # --- Let user choose metric ---
        metric_options = ["cpu_percent", "energy_estimate"]
        metric = st.selectbox("Select metric to compare:", metric_options)

        # --- Side-by-side averages ---
        st.subheader(f"{metric} Comparison")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown(f"**eBPF Model Average ({metric})**")
            ebpf_avg = round(df_ebpf[metric].mean(), 2)
            st.metric(label="eBPF Average", value=ebpf_avg)

        with col2:
            st.markdown(f"**Baseline Model Average ({metric})**")
            base_avg = round(df_base[metric].mean(), 2)
            st.metric(label="Baseline Average", value=base_avg)

        # --- Dynamic Conclusion ---
        st.subheader("Conclusion")
        delta = base_avg - ebpf_avg
        if delta > 0:
            st.markdown(f"- **{metric}** → eBPF performs better (lower is better).")
        elif delta < 0:
            st.markdown(f"- **{metric}** → Baseline performs better (lower is better).")
        else:
            st.markdown(f"- **{metric}** → Performance is equal.")

        # --- Graph Visualization ---
        st.subheader(f"{metric} Trend Comparison")
        fig, ax = plt.subplots(figsize=(10,4))
        ax.plot(df_ebpf[metric].values, color="#00b4d8", label="eBPF")
        ax.plot(df_base[metric].values, color="#ff7f50", label="Baseline")
        ax.set_xlabel("Time / Index", color='white')
        ax.set_ylabel(metric, color='white')
        ax.set_title(f"{metric} Comparison Over Time", color="#00b4d8")
        ax.legend(facecolor="#111827", labelcolor='white')
        ax.set_facecolor('#111827')
        fig.patch.set_facecolor('#0e1117')
        ax.tick_params(colors='white')
        st.pyplot(fig)

    else:
        st.warning("Required CSV files not found! Make sure 'system_monitor_log.csv' and 'baseline_monitor_log.csv' exist.")


# --- PAGE 5: About ---
elif page == "About":
    st.title("💡 About the Project")

    st.markdown("""
    ## ⚙️ Energy-Aware System Monitoring using eBPF

    This project presents an **intelligent, energy-efficient system monitoring dashboard** that leverages the power of **eBPF (Extended Berkeley Packet Filter)** to collect kernel-level metrics in real time.  
    The dashboard offers comprehensive insights into **CPU usage, system calls, context switches, and energy estimation**—all visualized through a modern dark-themed interface.


    ### 🧠 Project Overview
    - Combines **Kernel-Space (eBPF)** and **User-Space (psutil)** monitoring  
    - Real-time tracking and visualization of system performance  
    - **Comparison Mode** to evaluate eBPF-based monitoring vs. traditional baseline models  
    - **Energy Efficiency Analysis** through CSV-based log comparison  
    - **User-Friendly Interface** built using **Streamlit** with a professional dark theme  



    ### 👩‍💻 Developed By Our Team
    **Group Members:**
    - Anmol Kumari  
    - Eman Saleem
    - Alizay Ahmed 
    - Muskan 


    ### 🧩 Tools & Technologies
    - **eBPF** for kernel-level event monitoring  
    - **Python (psutil, pandas, matplotlib)** for user-space data processing  
    - **Streamlit** for interactive dashboards  
    - **Linux / Ubuntu Environment** for real-time data collection  



    ### 🎯 Objectives
    - Reduce energy consumption through efficient kernel level monitoring  
    - Improve accuracy and depth of system insights  
    - Compare traditional vs. eBPF-based performance monitoring models  
 

    ### 🏁 Key Outcome
    Our eBPF-based system demonstrates **better energy optimization and lower overhead** compared to conventional methods, making it an ideal solution for modern, resource-sensitive environments.
    """)

    st.success("🚀 Project successfully completed with collaborative effort and innovation by the entire team!")

