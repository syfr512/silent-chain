# Silent Chain - Asynchronous AI-Assisted Telemetry Analyzer

<!-- ![Silent Chain Logo Placeholder](docs/images/logo_placeholder.png) -->

## Description

**Silent Chain** is a powerful, passive Burp Suite Community extension that routes intercepted HTTP traffic telemetry to Large Language Models (LLMs) for real-time vulnerability correlation and attack-path analysis. Built for flexibility and privacy, it allows security researchers to seamlessly dispatch traffic to either localized offline models (via Ollama) or external cloud providers (like OpenAI) without interrupting their standard testing workflow.

## Key Features

- **Asynchronous LinkedBlockingQueue:** Extracts structural HTML, forms, and parameter telemetry passively using `IHttpListener`. All data is processed via a decoupled background thread (`Runnable`), ensuring zero UI lag or blocking in the main Burp Suite interface.
- **Native Java Bridge:** Intentionally bypasses Jython's occasionally unstable `urllib2` network stack in favor of native JVM classes (`java.net.HttpURLConnection`). This provides robust, non-blocking connections capable of handling extended timeouts required by local offline models.
- **Dynamic Dual-Mode Swing UI:** Features a custom, native Burp `ITab` interface built with `javax.swing`. Easily toggle between "Local (Ollama)" and "Cloud (OpenAI)" analysis modes on-the-fly without needing to edit or reload the script.
- **Optimized Plain-Text Output:** Enforces strict systemic prompting to strip the LLM response of Markdown syntax. Vulnerability findings are streamed natively into a beautifully padded, scrollable `JTextArea` using clean, professional ASCII formatting.

## Architecture Overview

Silent Chain follows a lightweight, non-intrusive data pipeline:

1. **Interception Hook:** The script monitors proxy traffic using Burp's `processHttpMessage` callback. Static assets (e.g., `.jpg`, `.css`) are proactively filtered to optimize LLM processing overhead.
2. **Telemetry Construction:** Extracts interesting headers, structural parameters, and form layouts into a minimized JSON dictionary.
3. **Queue Ingestion:** The dictionary is safely pushed to a bounded `LinkedBlockingQueue`, dropping packets if the queue is full to protect memory constraints.
4. **Background Dispatch:** A detached worker thread retrieves the telemetry, evaluates the current UI execution mode, and formats the payload appropriately for the target API.
5. **Local/Cloud Routing:** The payload is sent via a native Java HTTP request to the selected endpoint. The results are safely rendered back to the Burp Suite UI thread using `SwingUtilities.invokeLater`.

## Pre-requisites & Hardware Optimization

- **Burp Suite:** Community or Professional edition.
- **Jython 2.7:** Standalone `.jar` configured in Burp's *Extensions > Python Environment* settings.
- **Ollama:** Installed locally (or remotely) to handle local edge processing.

### Optimizing for Legacy Hardware
Silent Chain is designed to work well even on older hardware (e.g., Intel i5 CPUs with DDR3 memory). If you are running the extension without a dedicated GPU:
- **Deploy Micro-Models:** Use highly quantized, smaller models optimized for CPU inference, such as `llama3.2:1b` or `gemma3:2b`.
- **Infinite Timeouts:** The extension's native Java connection logic natively sets `conn.setReadTimeout(0)` when communicating with the local model, ensuring the connection remains stable even if CPU generation takes several minutes.

## Quick Start / Installation

1. **Setup Ollama (Local Mode):**
   - Download and install [Ollama](https://ollama.ai/).
   - Pull your preferred micro-model via terminal: `ollama run llama3.2:1b`
2. **Configure Burp Suite:**
   - Navigate to *Extensions > Python Environment* and load your `jython-standalone-2.7.x.jar`.
3. **Load Silent Chain:**
   - Download `silent_chain.py` from this repository.
   - In Burp Suite, go to the *Extensions* tab, click **Add**, select *Python* as the extension type, and locate `silent_chain.py`.
4. **View Output:**
   - Once loaded, navigate to the newly created **Silent Chain** top-level tab in Burp Suite to view the settings bar and incoming vulnerability reports.

## Configuration

You can seamlessly manage the extension's execution state via the **Silent Chain** UI tab:

- **Execution Mode Radio Buttons:** 
  - **Local (Ollama):** Routes all telemetry to `http://localhost:11434/api/generate`.
  - **Cloud (OpenAI):** Routes telemetry to OpenAI's completion endpoint (Requires API key configuration).

### Code Variables
If you need to change default models or keys, edit the top `CONFIGURATION` block in `silent_chain.py`:
```python
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"

OPENAI_API_KEY = "PLACE_YOUR_SECRET_KEY_HERE"
```
```
