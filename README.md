# 🛡️ DOM XSS Detector – Burp Suite Extension (Phase 1)

A lightweight Burp Suite extension written in Python (Jython) to detect potential **DOM-based XSS sinks** in HTTP responses. This helps security researchers and pen-testers surface risky JavaScript functions during web assessments.

---

## 🔍 Features

- Hooks into Burp Suite as an `IHttpListener`
- Scans HTTP **responses** in real-time
- Detects dangerous DOM XSS sinks, e.g.:
  - `document.write` / `document.writeln`
  - `document.location`, `location.href`, `location.replace`
  - `eval`, `setTimeout`, `setInterval`
  - `innerHTML`, `outerHTML`, `window.name`
  - `localStorage`, `sessionStorage`, `document.URL`, `document.referrer`
- Outputs findings (URL + sinks) to **Extender → Output** tab in Burp

---

## 🧠 How It Works

1. Burp invokes `processHttpMessage()` on each response.
2. The script extracts the response body (skipping headers).
3. It checks for any DOM sink keywords from its predefined list.
4. If found, prints a summary (URL + detected sinks) to Burp’s console.

---

## ⚙️ Installation

### Requirements
- **Burp Suite** (Community or Pro)
- **Jython standalone JAR** (for Python support)

### Installation Steps
1. Launch Burp Suite.
2. Go to **Extender → Options → Python Environment** and select your Jython JAR.
3. Go to **Extender → Extensions → Add**:
   - Extension type: `Python`
   - Extension file: `DomReflector.py`
4. Check **Extender → Output** for:
