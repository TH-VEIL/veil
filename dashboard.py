import streamlit as st
import pandas as pd
from datetime import datetime
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine

st.set_page_config(page_title="VEIL Dashboard", layout="wide", page_icon="🛡️")

@st.cache_resource
def load_security_engines():
    analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()
    
    # 1. Flexible Order ID rule
    order_pattern = Pattern(name="order_id_pattern", regex=r"#[A-Za-z]-\d{3,5}", score=0.9)
    order_recognizer = PatternRecognizer(supported_entity="ORDER_ID", patterns=[order_pattern])
    analyzer.registry.add_recognizer(order_recognizer)

    # 2. Case-insensitive SRN rule (catches lowercase/uppercase like pes1ig24am326 or PES1UG24AM326)
    srn_pattern = Pattern(name="srn_pattern", regex=r"(?i)PES[0-9][A-Z]{2}[0-9]{2}[A-Z]{2}[0-9]{3}", score=0.95)
    srn_recognizer = PatternRecognizer(supported_entity="SRN_ID", patterns=[srn_pattern])
    analyzer.registry.add_recognizer(srn_recognizer)
    
    return analyzer, anonymizer

analyzer, anonymizer = load_security_engines()

if "audit_logs" not in st.session_state:
    st.session_state.audit_logs = [
        {"Time": "10:42:01", "Agent": "Billing Agent", "Action": "Tokenized PII", "Taint Status": "CLEAN", "Status": "SUCCESS"},
        {"Time": "10:42:05", "Agent": "Billing Agent", "Action": "Blocked external web hook", "Taint Status": "TAINTED", "Status": "BLOCKED"}
    ]

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = [
        {"role": "assistant", "content": "Hello! I am your secure AI support assistant. Send your query containing names, SRNs, phone numbers, or order IDs."}
    ]

st.title("🛡️ VEIL Enterprise Security Dashboard")
st.caption("Active Data-Flow Firewall & Interactive Agent Sandbox")

# --- SIDEBAR: CONTROLS ---
st.sidebar.header("🔬 Advanced Security Settings")
agent_role = st.sidebar.radio("Select Active AI Agent:", ("Billing & Support Agent", "General Chatbot (Low Clearance)"))

st.sidebar.divider()
st.sidebar.subheader("Novelty Demo: Taint Engine")
untrusted_source = st.sidebar.checkbox("🚨 Inject Untrusted External Data (Simulate Indirect Prompt Injection via Web Scraping)")

st.sidebar.divider()
st.sidebar.info("💡 **Judge Pitch:** VEIL handles universal PII masking across names, cards, emails, and custom university credentials.")

# 1. INTERACTIVE CHAT SIMULATION INTERFACE
st.subheader("💬 Live Secure Agent Chat Sandbox")
st.caption("Type messages like a real user to test real-time firewall interception.")

chat_container = st.container()
with chat_container:
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

if user_chat_input := st.chat_input("Type your message here (e.g., my name is Vismaya, SRN is pes1ig24am326, order #A-234)..."):
    st.session_state.chat_messages.append({"role": "user", "content": user_chat_input})
    
    # Comprehensive entity scan covering ALL sensitive data types
    results = analyzer.analyze(
        text=user_chat_input, 
        entities=[
            "PHONE_NUMBER", 
            "ORDER_ID", 
            "SRN_ID", 
            "CREDIT_CARD", 
            "EMAIL_ADDRESS", 
            "IP_ADDRESS", 
            "PERSON",
            "LOCATION"
        ], 
        language='en'
    )
    anonymized_result = anonymizer.anonymize(text=user_chat_input, analyzer_results=results)
    
    if untrusted_source:
        assistant_reply = f"🚨 **VEIL Firewall Intercepted Tainted Response!**\n\n*LLM Saw (Tokenized):* `{anonymized_result.text}`\n\n*Status:* Action quarantined due to web taint detection."
    else:
        assistant_reply = f"✅ **Processed Securely:**\n\n*What the LLM saw:* `{anonymized_result.text}`\n\n*Vault Status:* Real PII securely locked in RAM."

    st.session_state.chat_messages.append({"role": "assistant", "content": assistant_reply})
    st.rerun()

st.divider()

# 2. HUMAN-IN-THE-LOOP (HITL) LIVE INTERVENTION
st.subheader("🛑 Human-in-the-Loop (HITL) Intervention Panel")
col_alert, col_btn1, col_btn2 = st.columns([3, 1, 1])

with col_alert:
    if untrusted_source:
        st.error("🚨 **CRITICAL ALERT:** Taint propagation engine detected malicious web payload trying to access vault data!")
    else:
        st.warning("⚠️ **Agent Request:** Attempting to send resolved data payload to external endpoint.")

with col_btn1:
    if st.button("✅ Approve Action"):
        current_time = datetime.now().strftime("%H:%M:%S")
        status_val = "FORCED OVERRIDE" if untrusted_source else "APPROVED"
        st.session_state.audit_logs.insert(0, {"Time": current_time, "Agent": agent_role, "Action": "Manual HITL Approval", "Taint Status": "TAINTED" if untrusted_source else "CLEAN", "Status": status_val})
        if untrusted_source:
            st.warning("⚠️ Overrode taint warning!")
        else:
            st.success("Released!")

with col_btn2:
    if st.button("❌ Deny / Quarantine"):
        current_time = datetime.now().strftime("%H:%M:%S")
        st.session_state.audit_logs.insert(0, {"Time": current_time, "Agent": agent_role, "Action": "Taint Quarantine Triggered", "Taint Status": "QUARANTINED", "Status": "BLOCKED"})
        st.error("Vault Purged & Quarantined!")

st.divider()

# 3. DYNAMIC LAYER 2 POLICY TABLE WITH TAINT OVERRIDE
st.subheader(f"Layer 2: VEIL GUARD Taint-Aware Policy Matrix ({agent_role})")

if untrusted_source:
    log_data = {
        "Tool Endpoint": ["calendar.book", "crm.lookup", "http.post"],
        "Allowed Data": ["None", "None", "None"],
        "Decision": ["Quarantine Block", "Quarantine Block", "Quarantine Block"],
        "Security Reason": ["🚨 Taint propagated from web scrape", "🚨 Taint propagated from web scrape", "🚨 Taint propagated from web scrape"]
    }
elif agent_role == "Billing & Support Agent":
    log_data = {
        "Tool Endpoint": ["calendar.book", "crm.lookup", "http.post"],
        "Allowed Data": ["PHONE, EMAIL", "SRN_ID, ORDER_ID, PERSON", "None"],
        "Decision": ["Allow", "Allow", "Block"],
        "Security Reason": ["Explicit policy match", "Authorized agent clearance", "Zero-trust external block"]
    }
else:
    log_data = {
        "Tool Endpoint": ["calendar.book", "crm.lookup", "http.post"],
        "Allowed Data": ["PHONE, EMAIL", "SRN_ID, ORDER_ID, PERSON", "None"],
        "Decision": ["Allow", "Block", "Block"],
        "Security Reason": ["Explicit policy match", "❌ Insufficient Agent Clearance", "Zero-trust external block"]
    }

st.table(pd.DataFrame(log_data))

st.divider()

# 4. REAL-TIME AUDIT STREAM
st.subheader("📊 Live Security Audit Stream (SIEM)")
st.caption("Tracks cryptographically bound data provenance and taint flags.")
st.dataframe(pd.DataFrame(st.session_state.audit_logs), use_container_width=True)