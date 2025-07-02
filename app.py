import streamlit as st
import subprocess
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="PQC vs Classical Crypto", layout="centered")
st.title("🔐 PQC vs Classical Crypto Performance Benchmark")

# Run the benchmark executable
st.markdown("### Running benchmark...")
try:
    output = subprocess.check_output(["./benchmark"], universal_newlines=True)
    st.code(output)
except Exception as e:
    st.error(f"❌ Failed to run benchmark: {e}")
    st.stop()

# Parse the output
times = {}
sizes = {}

for line in output.splitlines():
    try:
        if any(kw in line for kw in ["KeyGen", "Encaps", "Decaps", "Encrypt", "Decrypt"]):
            label, val = line.split(":")
            times[label.strip()] = float(val.strip().split()[0].lstrip("~"))
        elif "Key Size" in line or "Ciphertext Size" in line or "Public Key" in line or "Private Key" in line:
            label, val = line.split(":")
            sizes[label.strip()] = int(val.strip().split()[0].lstrip("~"))
    except:
        st.warning(f"⚠️ Could not parse line: {line}")

# Plot time comparisons using Plotly
if times:
    st.markdown("## ⏱️ Time Comparisons")
    time_labels = list(times.keys())
    time_values = list(times.values())

    fig_time = px.bar(
        x=time_values,
        y=time_labels,
        orientation='h',
        color=time_labels,
        labels={"x": "Time (seconds)", "y": "Operation"},
        title="Operation Times: PQC vs Classical Crypto",
        height=400
    )
    st.plotly_chart(fig_time, use_container_width=True)

# Plot size comparisons using Plotly
if sizes:
    st.markdown("## 📦 Key and Ciphertext Sizes")
    size_labels = list(sizes.keys())
    size_values = list(sizes.values())

    fig_size = px.bar(
        x=size_values,
        y=size_labels,
        orientation='h',
        color=size_labels,
        labels={"x": "Size (bytes)", "y": "Key / Ciphertext"},
        title="Key & Ciphertext Sizes: PQC vs Classical Crypto",
        height=400
    )
    st.plotly_chart(fig_size, use_container_width=True)

