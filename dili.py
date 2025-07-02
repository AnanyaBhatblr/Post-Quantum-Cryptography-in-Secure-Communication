import streamlit as st
import subprocess

st.set_page_config(page_title="Dilithium Signature Demo", layout="centered")
st.title("🔐 Dilithium Signature Verification Demo")

# Sidebar: Main modes
mode = st.sidebar.radio("Select Mode", [
    "🔐 Signature Tabs",
    "📄 Placeholder (other mode)"
])

# Utility to run shell commands and capture output
def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode().strip().splitlines()
    except subprocess.CalledProcessError as e:
        return [f"❌ Error occurred:\n{e.output.decode().strip()}"]


# 🧠 Beautifier to format output
def display_output(title, lines):
    st.markdown(f"#### 📤 {title}")
    formatted = "\n".join(lines)
    st.code(formatted, language="bash")  # Terminal-style formatting


# 🔐 Signature Workflow Tabs
if mode == "🔐 Signature Tabs":
    tab1, tab2, tab3 = st.tabs(["✅ Actual Client", "🚨 Fake Client", "🛡️ Server"])

    # ✅ Actual Client
    with tab1:
        st.subheader("✅ Valid Client Signer")
        msg = st.text_input("Enter message to sign and send:", key="actual_input")

        if st.button("📝 Sign & Send (Valid Client)", key="actual_btn") and msg.strip():
            output_lines = run_command(f"./client_dilithium1 \"{msg}\"")
            display_output("Valid Client Output", output_lines)

    # 🚨 Fake Client
    with tab2:
        st.subheader("🚨 Malicious Client")
        msg = st.text_input("Enter message to sign and send:", key="fake_input")

        if st.button("⚠️ Sign & Send (Fake Client)", key="fake_btn") and msg.strip():
            output_lines = run_command(f"./client_invalid \"{msg}\"")
            display_output("Fake Client Output", output_lines)

    # 🛡️ Server
    with tab3:
        st.subheader("🛡️ Server Verifier")

        if st.button("📥 Receive & Verify Signature", key="server_btn"):
            output_lines = run_command("./server_dilithium")
            display_output("Server Output", output_lines)

            result_block = "\n".join(output_lines).lower()
            if "✅" in result_block or "signature is valid" in result_block:
                st.success("✅ Signature is VALID. The message came from a trusted client.")
            elif "❌" in result_block or "signature is invalid" in result_block:
                st.error("❌ Signature is INVALID. The message may be forged or tampered.")

# 📄 Placeholder Tab
elif mode == "📄 Placeholder (other mode)":
    st.info("📌 This is a placeholder for future modules.")
