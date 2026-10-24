# 🛡️ VEIL: Enterprise PII Protection & Taint-Aware LLM Firewall

VEIL is an advanced, enterprise-grade data-flow firewall and interactive security dashboard designed to prevent prompt injection and automatically tokenize sensitive PII before it ever reaches an LLM.

## 🚀 Key Features

* **Layer 1: Universal PII Tokenization & Masking**
  * Powered by Microsoft Presidio (`AnalyzerEngine` & `AnonymizerEngine`).
  * Real-time masking for **Names, Emails, Phone Numbers, Credit Cards, and IP Addresses**.
  * Custom enterprise regex pattern matching for **University SRNs** (e.g., case-insensitive support like `pes1ig24am326`) and **Order IDs** (e.g., `#A-234`).
* **Layer 2: Taint-Aware Policy Matrix**
  * Dynamic security policy enforcement depending on the active AI agent role (e.g., Billing & Support vs. Low-Clearance Chatbot).
  * Automatic quarantine blocks when external untrusted data taint is detected.
* **Human-in-the-Loop (HITL) Intervention Panel**
  * Real-time security alerts allowing administrators to approve, override, or purge tainted data payloads before external tool execution.
* **Live SIEM Audit Stream**
  * Tracks cryptographically bound data provenance, action timestamps, and security decisions.

---

## 🛠️ Tech Stack

* **Frontend & Dashboard:** Streamlit
* **Security & NLP Engine:** Microsoft Presidio, spaCy (`en_core_web_lg`)
* **Data Processing:** Pandas, Python AsyncIO

---

## ⚙️ Local Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/TH-VEIL/Veil_Guard.git](https://github.com/TH-VEIL/Veil_Guard.git)
   cd Veil_Guard
