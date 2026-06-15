# Silent Chain - Burp Suite Community Extension
# Jython 2.7 compatible
# Authorized testing only.

from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter, BufferedReader, InputStreamReader, OutputStreamWriter
from java.lang import Runnable, Thread, Exception as JavaException
from java.net import URL
from java.util.concurrent import LinkedBlockingQueue
from javax.swing import JScrollPane, JTextArea, SwingUtilities, JPanel, JLabel, JRadioButton, ButtonGroup
from java.awt import Component, BorderLayout, FlowLayout
from java.awt.event import ActionListener

import urllib2
import json
import ssl
import re
import time

# =========================
# CONFIGURATION
# =========================

AI_MODE = "LOCAL" # Options: "CLOUD" or "LOCAL"

# Local AI Configuration (Ollama)
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"

# Cloud AI Configuration (OpenAI)
OPENAI_API_KEY = "PLACE_YOUR_SECRET_KEY_HERE"
OPENAI_ENDPOINT = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"

# Targeting modes:
# "SCOPE_ONLY"      = only analyze sites manually added to Burp Target Scope
# "AUTO_ALLOWLIST"  = automatically allow the first few real hosts you browse
# "ALLOW_ALL"       = analyze every non-static host Burp sees; expensive/noisy
TARGET_MODE = "AUTO_ALLOWLIST"
AUTO_ALLOWED_HOSTS = []
MAX_HOSTS_AUTO_ALLOW = 5

MAX_QUEUE_SIZE = 25
API_TIMEOUT_SECONDS = 35
MAX_BODY_CHARS = 6000
MIN_SECONDS_BETWEEN_API_CALLS = 2

DROP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov", ".zip", ".rar", ".7z",
    ".pdf"
)

INTERESTING_HEADERS = (
    "host:",
    "content-type:",
    "location:",
    "set-cookie:",
    "cookie:",
    "authorization:",
    "referer:",
    "origin:",
    "x-forwarded-for:",
    "x-real-ip:",
    "server:",
    "x-powered-by:"
)


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Silent Chain - Cloud API")
        
        # UI Setup
        self.main_panel = JPanel(BorderLayout())
        
        # Top Panel
        self.top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.top_panel.add(JLabel("Execution Mode:"))
        
        self.radio_local = JRadioButton("Local (Ollama)")
        self.radio_cloud = JRadioButton("Cloud (OpenAI)")
        
        mode_group = ButtonGroup()
        mode_group.add(self.radio_local)
        mode_group.add(self.radio_cloud)
        
        if AI_MODE == "LOCAL":
            self.radio_local.setSelected(True)
        else:
            self.radio_cloud.setSelected(True)
            
        class ModeChangeListener(ActionListener):
            def __init__(self, mode):
                self.mode = mode
            def actionPerformed(self, event):
                global AI_MODE
                AI_MODE = self.mode
                
        self.radio_local.addActionListener(ModeChangeListener("LOCAL"))
        self.radio_cloud.addActionListener(ModeChangeListener("CLOUD"))
        
        self.top_panel.add(self.radio_local)
        self.top_panel.add(self.radio_cloud)
        
        self.main_panel.add(self.top_panel, BorderLayout.NORTH)
        
        # Bottom Panel (Text Area)
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setLineWrap(True)
        self.log_area.setWrapStyleWord(True)
        self.scroll_pane = JScrollPane(self.log_area)
        self.main_panel.add(self.scroll_pane, BorderLayout.CENTER)
        
        callbacks.addSuiteTab(self)
        
        callbacks.registerHttpListener(self)

        self.queue = LinkedBlockingQueue(MAX_QUEUE_SIZE)
        self.worker = SilentChainWorker(self)
        self.worker_thread = Thread(self.worker)
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()

        self.stdout.println("[Silent Chain] Loaded successfully.")
        self.stdout.println("[Silent Chain] Target mode: " + TARGET_MODE)
        self.stdout.println("[Silent Chain] AUTO_ALLOWLIST max hosts: " + str(MAX_HOSTS_AUTO_ALLOW))
        self.stdout.println("[Silent Chain] Worker thread started.")
        self.stdout.println("[Silent Chain] Replace OPENAI_API_KEY before running real scans.")

    # ITab implementation
    def getTabCaption(self):
        return "Silent Chain"

    def getUiComponent(self):
        return self.main_panel

    def append_to_ui(self, message):
        class AppendTask(Runnable):
            def __init__(self, text_area, text):
                self.text_area = text_area
                self.text = text
            def run(self):
                self.text_area.append(self.text + "\n")
                self.text_area.setCaretPosition(self.text_area.getDocument().getLength())
        
        SwingUtilities.invokeLater(AppendTask(self.log_area, message))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            if messageIsRequest:
                return

            request_info = self.helpers.analyzeRequest(messageInfo)
            url_obj = request_info.getUrl()
            url = str(url_obj)

            if not self.is_allowed_target(url_obj):
                return

            if self.is_static_asset(url):
                return

            response = messageInfo.getResponse()
            if response is None:
                return

            response_info = self.helpers.analyzeResponse(response)
            telemetry = self.build_minimal_telemetry(messageInfo, request_info, response_info)

            if telemetry is None:
                return

            accepted = self.queue.offer(telemetry)
            if not accepted:
                self.stdout.println("[Silent Chain] Queue full. Dropped telemetry to protect Burp UI.")

        except Exception as e:
            self.stderr.println("[Silent Chain] Listener error: " + str(e))


    def is_allowed_target(self, url_obj):
        """
        Decides whether this host should be analyzed.
        This replaces the old hardcoded testfire.net / scope-only behavior.
        """
        try:
            host = str(url_obj.getHost()).lower()
        except:
            return False

        if TARGET_MODE == "SCOPE_ONLY":
            return self.callbacks.isInScope(url_obj)

        if TARGET_MODE == "ALLOW_ALL":
            return True

        if TARGET_MODE == "AUTO_ALLOWLIST":
            if host in AUTO_ALLOWED_HOSTS:
                return True

            if len(AUTO_ALLOWED_HOSTS) < MAX_HOSTS_AUTO_ALLOW:
                AUTO_ALLOWED_HOSTS.append(host)
                self.stdout.println("[Silent Chain] Auto-added host: " + host)
                return True

            self.stdout.println("[Silent Chain] Auto-allowlist full. Dropped host: " + host)
            return False

        self.stdout.println("[Silent Chain] Unknown TARGET_MODE. Falling back to SCOPE_ONLY.")
        return self.callbacks.isInScope(url_obj)


    def is_static_asset(self, url):
        lower_url = url.lower().split("?")[0]
        for ext in DROP_EXTENSIONS:
            if lower_url.endswith(ext):
                return True
        return False

    def build_minimal_telemetry(self, messageInfo, request_info, response_info):
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()

        url = str(request_info.getUrl())
        method = request_info.getMethod()
        status_code = response_info.getStatusCode()

        req_headers = self.filter_headers(request_info.getHeaders())
        resp_headers = self.filter_headers(response_info.getHeaders())

        params = []
        for p in request_info.getParameters():
            try:
                params.append({
                    "name": str(p.getName()),
                    "value_sample": self.safe_sample(str(p.getValue()), 80),
                    "type": int(p.getType())
                })
            except:
                pass

        body_offset = response_info.getBodyOffset()
        body = self.helpers.bytesToString(response[body_offset:])
        structural_html = self.extract_structural_html(body)

        telemetry = {
            "timestamp": int(time.time()),
            "url": url,
            "method": method,
            "status_code": int(status_code),
            "request_headers": req_headers,
            "response_headers": resp_headers,
            "parameters": params,
            "forms_and_inputs": structural_html
        }

        return telemetry

    def filter_headers(self, headers):
        kept = []
        try:
            for h in headers:
                hs = str(h)
                hsl = hs.lower()
                for prefix in INTERESTING_HEADERS:
                    if hsl.startswith(prefix):
                        kept.append(self.safe_sample(hs, 300))
                        break
        except:
            pass
        return kept

    def extract_structural_html(self, body):
        if body is None:
            return ""

        body = body[:MAX_BODY_CHARS]

        findings = []

        forms = re.findall(r"(?is)<form[^>]*>.*?</form>", body)
        for f in forms[:5]:
            action = self.regex_attr(f, "action")
            method = self.regex_attr(f, "method")
            inputs = re.findall(r"(?is)<input[^>]*>", f)
            selects = re.findall(r"(?is)<select[^>]*>", f)
            textareas = re.findall(r"(?is)<textarea[^>]*>", f)

            fields = []
            for tag in inputs[:20]:
                fields.append({
                    "tag": "input",
                    "name": self.regex_attr(tag, "name"),
                    "type": self.regex_attr(tag, "type"),
                    "value_sample": self.safe_sample(self.regex_attr(tag, "value"), 80)
                })

            for tag in selects[:10]:
                fields.append({
                    "tag": "select",
                    "name": self.regex_attr(tag, "name")
                })

            for tag in textareas[:10]:
                fields.append({
                    "tag": "textarea",
                    "name": self.regex_attr(tag, "name")
                })

            findings.append({
                "form_action": action,
                "form_method": method,
                "fields": fields
            })

        links = []
        for href in re.findall(r"(?is)<a[^>]+href=[\"']([^\"']+)[\"']", body):
            href = href.strip()
            if href and len(links) < 20:
                links.append(self.safe_sample(href, 200))

        scripts = []
        for src in re.findall(r"(?is)<script[^>]+src=[\"']([^\"']+)[\"']", body):
            src = src.strip()
            if src and len(scripts) < 10:
                scripts.append(self.safe_sample(src, 200))

        return {
            "forms": findings,
            "links_sample": links,
            "script_src_sample": scripts
        }

    def regex_attr(self, tag, attr):
        try:
            pattern = r"(?is)\s" + re.escape(attr) + r"\s*=\s*[\"']([^\"']*)[\"']"
            m = re.search(pattern, tag)
            if m:
                return m.group(1).strip()
        except:
            pass
        return ""

    def safe_sample(self, s, max_len):
        if s is None:
            return ""
        s = s.replace("\r", " ").replace("\n", " ").strip()
        if len(s) > max_len:
            return s[:max_len] + "...[truncated]"
        return s


class SilentChainWorker(Runnable):

    def __init__(self, extender):
        self.extender = extender
        self.last_call = 0

    def run(self):
        out = self.extender.stdout
        err = self.extender.stderr

        while True:
            try:
                telemetry = self.extender.queue.take()

                now = time.time()
                delta = now - self.last_call
                if delta < MIN_SECONDS_BETWEEN_API_CALLS:
                    time.sleep(MIN_SECONDS_BETWEEN_API_CALLS - delta)

                result = self.query_ai_backend(telemetry)
                self.last_call = time.time()

                log_entry = (
                    "\n========== Silent Chain %s Analysis ==========\n" % AI_MODE +
                    "URL: " + str(telemetry.get("url", "")) + "\n" +
                    (result if result else "[Error] No result returned.") + "\n" +
                    "=================================================\n"
                )

                # Print to standard output (extender console)
                out.println(log_entry)
                
                # Print to the custom UI tab safely
                self.extender.append_to_ui(log_entry)

            except Exception as e:
                err.println("[Silent Chain] Worker error: " + str(e))

    def make_java_http_request(self, endpoint_url, payload_dict, headers=None):
        if headers is None:
            headers = {}
        try:
            url = URL(endpoint_url)
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            for key, value in headers.items():
                conn.setRequestProperty(key, value)
            conn.setDoOutput(True)
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(0)
            
            writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            writer.write(json.dumps(payload_dict))
            writer.flush()
            writer.close()
            
            status_code = conn.getResponseCode()
            if status_code >= 400:
                reader = BufferedReader(InputStreamReader(conn.getErrorStream(), "UTF-8"))
            else:
                reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
                
            response_lines = []
            line = reader.readLine()
            while line is not None:
                response_lines.append(line)
                line = reader.readLine()
            reader.close()
            
            response_data = "".join(response_lines)
            
            if status_code >= 400:
                return None, "[HTTP Error %s] %s" % (status_code, response_data)
                
            return json.loads(response_data), None
            
        except JavaException as e:
            return None, "[Java Network Exception] " + e.getMessage()
        except Exception as e:
            return None, "[Python Exception] " + str(e)

    def query_ai_backend(self, telemetry):
        system_prompt = (
            "You are Silent Chain, a defensive web security analysis assistant. "
            "Analyze only authorized lab traffic. "
            "Return concise cybersecurity attack-path analysis for the observed request/response. "
            "Focus on likely vulnerabilities, evidence from telemetry, risk, and safe validation steps. "
            "Do not provide destructive exploitation instructions, persistence, evasion, malware, or data theft guidance. "
            "CRITICAL FORMATTING RULES: "
            "NEVER use Markdown syntax. Do not output asterisks (*), hashtags (#), or bolding. "
            "Format your response as a professional plain-text corporate report. "
            "Use clean spacing, proper indentations, and standard ASCII bullet points (-) or arrows (-->)."
        )

        user_prompt = (
            "Analyze this Burp telemetry from an authorized lab target. "
            "Identify possible attack chains and defensive validation checks. "
            "Keep output practical and concise.\n\n"
            + json.dumps(telemetry, separators=(",", ":"))
        )

        if AI_MODE == "LOCAL":
            # Ollama API format
            payload = {
                "model": OLLAMA_MODEL,
                "prompt": system_prompt + "\n\n" + user_prompt,
                "stream": False
            }
            
            self.extender.stdout.println("[*] Waiting for local AI response (this may take a moment on CPU)...")
            parsed, err = self.make_java_http_request(OLLAMA_ENDPOINT, payload)
            if err:
                return "[Ollama Error] " + err
            if parsed and "response" in parsed:
                return parsed["response"].strip()
            return "[Ollama Error] Invalid response format"

        elif AI_MODE == "CLOUD":
            if OPENAI_API_KEY == "PLACE_YOUR_SECRET_KEY_HERE":
                return "[Config Error] Set OPENAI_API_KEY at the top of the extension file."

            payload = {
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 700
            }

            headers = {
                "Authorization": "Bearer " + OPENAI_API_KEY
            }

            parsed, err = self.make_java_http_request(OPENAI_ENDPOINT, payload, headers)
            if err:
                return "[OpenAI Error] " + err
            if parsed and "choices" in parsed and len(parsed["choices"]) > 0:
                return parsed["choices"][0]["message"]["content"].strip()
            return "[OpenAI Error] Invalid response format"
            
        return "[Config Error] Unknown AI_MODE: " + str(AI_MODE)
