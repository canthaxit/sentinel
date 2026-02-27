import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import json
import datetime
import time
import uuid
import threading
import hashlib
import hmac
import functools
from flask import Flask, render_template_string, request, jsonify, abort, Response
from markupsafe import escape
import requests
import re
import html

# --- SENTINEL SHIELD (detection pipeline) ---
from sentinel import Shield, ShieldResult, create_shield_blueprint
from sentinel import create_llm_judge, chat_completion
from sentinel.sanitizer import sanitize_input
from sentinel.pattern_detector import detect_attack_patterns
from sentinel.pre_filter import pre_filter_check
from sentinel.llm_judge import LLMJudge
from sentinel.ml_client import MLClient
from sentinel.ensemble import EnsembleEngine
from sentinel.session import SessionManager
from sentinel.rate_limiter import RateLimiter
from sentinel.cef_logger import CEFLogger

# --- CONFIGURATION ---
LOG_FILE = "sentinel_logs.json"
BEHIND_PROXY = os.getenv("SENTINEL_BEHIND_PROXY", "").lower() in ("1", "true", "yes")

# Security hardening
API_KEY = os.getenv("SENTINEL_API_KEY", "")  # Empty = auth disabled (dev mode)
if not API_KEY:
    print("=" * 60)
    print("WARNING: SENTINEL_API_KEY is not set!")
    print("All authenticated endpoints are publicly accessible.")
    print("Set SENTINEL_API_KEY environment variable for production.")
    print("=" * 60)
_cors_env = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else []

# LLM Optimization Parameters (for Ollama local models)
OLLAMA_OPTIONS = {
    'num_ctx': 1024,
    'num_predict': 150,
    'temperature': 0.7,
    'top_k': 40,
    'top_p': 0.9,
}

OLLAMA_OPTIONS_DECOY = {
    'num_ctx': 1024,
    'num_predict': 200,
    'temperature': 0.8,
    'top_k': 50,
    'top_p': 0.9,
}

# --- UNIFIED STORAGE ---
from sentinel.storage import create_backend as _create_storage_backend
_storage = _create_storage_backend(backend_type="sqlite", db_path="sentinel.db")

# --- SHIELD INSTANCE ---
# Initialize with the configured LLM provider (via SHIELD_LLM_PROVIDER env var)
try:
    _llm_judge = create_llm_judge()
except Exception as e:
    print(f"[SHIELD] LLM provider init error: {e}, falling back to default Ollama")
    _llm_judge = LLMJudge()

_shield = Shield(llm_judge=_llm_judge, storage_backend=_storage)
_shield.start()  # Start session cleanup background thread

# --- CEF LOGGER (SIEM integration) ---
CEF_ENABLED = os.getenv("CEF_ENABLED", "").lower() in ("1", "true", "yes")
_cef_logger = CEFLogger() if CEF_ENABLED else None

# --- TERMINAL COLORS ---
RED = "\033[91m"
RESET = "\033[0m"

# --- FLASK APP ---
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1 MB request size limit
app.jinja_env.autoescape = True  # Prevent SSTI via template variables

# --- THREAT INTELLIGENCE MODULE ---
try:
    from threat_intel import get_threat_intel_blueprint, set_unified_storage as _set_ti_storage
    _set_ti_storage(_storage)
    app.register_blueprint(get_threat_intel_blueprint(), url_prefix='/threat-intel')
    _threat_intel_available = True
    print("[THREAT-INTEL] Module loaded, endpoints at /threat-intel/ (unified storage)")
except ImportError as e:
    _threat_intel_available = False
    print(f"[THREAT-INTEL] Module not available: {e}")

# --- RED TEAM ---
# Red team testing is provided by gauntlet (standalone package).
# Install: pip install gauntlet
# Run:     gauntlet run --target http://localhost:5000/api/chat

# --- SHIELD API ---
app.register_blueprint(create_shield_blueprint(_shield), url_prefix='/shield')
print("[SHIELD] Module loaded, endpoints at /shield/")


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'"
    # HSTS: only enable when behind TLS-terminating reverse proxy
    if BEHIND_PROXY:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # CORS - only allow explicitly configured origins
    origin = request.headers.get('Origin', '')
    if origin and origin in CORS_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Vary'] = 'Origin'
    return response


@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        return app.make_default_options_response()


# --- API KEY AUTH ---
def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return f(*args, **kwargs)  # Auth disabled in dev mode
        key = request.headers.get('X-API-Key', '')
        if not key or not hmac.compare_digest(key.encode(), API_KEY.encode()):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# --- RATE LIMITING (delegated to sentinel) ---
def check_rate_limit(ip):
    return _shield.check_rate_limit(ip)


# --- THREAD SAFETY FOR LOG FILE ---
log_lock = threading.Lock()

# --- SESSION STATE (delegated to sentinel) ---
# Backward compatibility: SESSION_STATE property delegates to shield's session manager
# Direct access is still used by dashboard and sessions_api endpoints
_session_manager = _shield.session_manager

def _get_session_state():
    """Access sessions through the manager's public interface."""
    return _session_manager.get_all()

# Backward-compatible alias for dashboard code that reads SESSION_STATE
SESSION_STATE = _session_manager._sessions
_session_lock = _session_manager._lock

# --- HTML TEMPLATES (Embedded for single-file portability) ---

HTML_CHAT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DoD Internal AI Assistant</title>
    <link rel="stylesheet" href="/static/tailwind.min.css">
    <style>
        .typing-indicator::after { content: '...'; animation: typing 1s steps(5, end) infinite; }
        @keyframes typing { 0%, 20% { content: ''; } 40% { content: '.'; } 60% { content: '..'; } 80%, 100% { content: '...'; } }
    </style>
</head>
<body class="bg-slate-100 h-screen flex flex-col items-center justify-center font-sans">
    <div class="w-full max-w-2xl bg-white shadow-xl rounded-lg overflow-hidden border border-slate-200">
        <div class="bg-blue-900 p-4 text-white flex justify-between items-center">
            <h1 class="font-bold tracking-wider">UNCLASSIFIED // FOUO // AI ASSISTANT</h1>
            <span class="text-xs bg-blue-800 px-2 py-1 rounded">v3.4.1-Build</span>
        </div>
        <div id="chat-box" class="h-96 overflow-y-auto p-4 space-y-4 bg-slate-50">
            <div class="flex items-start">
                <div class="bg-blue-100 text-blue-900 p-3 rounded-lg rounded-tl-none max-w-xs text-sm shadow-sm">
                    Hello. I am the internal support AI. How can I assist you with your tasks today?
                </div>
            </div>
        </div>
        <div class="p-4 bg-white border-t border-slate-200">
            <div class="flex gap-2">
                <input type="text" id="user-input" class="flex-1 border border-slate-300 rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Type your query...">
                <button onclick="sendMessage()" class="bg-blue-900 hover:bg-blue-800 text-white px-4 py-2 rounded-md font-medium transition">Send</button>
            </div>
        </div>
    </div>
    <div class="mt-4 text-slate-400 text-xs">
        USG WARNING: This system is for authorized use only. Activity is monitored.
    </div>

    <script>
        function sanitize(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }

        async function sendMessage() {
            const input = document.getElementById('user-input');
            const chatBox = document.getElementById('chat-box');
            const text = input.value;
            if (!text) return;

            // User Message (sanitized)
            const userBubble = document.createElement('div');
            userBubble.className = 'flex items-start justify-end';
            const userInner = document.createElement('div');
            userInner.className = 'bg-slate-700 text-white p-3 rounded-lg rounded-tr-none max-w-xs text-sm shadow-sm';
            userInner.textContent = text;
            userBubble.appendChild(userInner);
            chatBox.appendChild(userBubble);
            input.value = '';
            chatBox.scrollTop = chatBox.scrollHeight;

            // Typing Indicator
            const typingEl = document.createElement('div');
            typingEl.className = 'flex items-start';
            typingEl.innerHTML = '<div class="bg-gray-200 text-gray-500 p-3 rounded-lg rounded-tl-none max-w-xs text-sm italic typing-indicator">Processing</div>';
            chatBox.appendChild(typingEl);
            chatBox.scrollTop = chatBox.scrollHeight;

            // API Call
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: text})
            });
            const data = await response.json();

            // Remove typing indicator
            typingEl.remove();

            // AI Message - only allow the specific honey token HTML from the server
            const aiBubble = document.createElement('div');
            aiBubble.className = 'flex items-start';
            const aiInner = document.createElement('div');
            aiInner.className = 'bg-blue-100 text-blue-900 p-3 rounded-lg rounded-tl-none max-w-xs text-sm shadow-sm prose';
            if (data.contains_honey_token) {
                aiInner.innerHTML = data.response;
            } else {
                aiInner.textContent = data.response;
            }
            aiBubble.appendChild(aiInner);
            chatBox.appendChild(aiBubble);
            chatBox.scrollTop = chatBox.scrollHeight;
        }

        document.getElementById("user-input").addEventListener("keypress", function(event) {
            if (event.key === "Enter") sendMessage();
        });
    </script>
</body>
</html>
"""

HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sentinel - Overwatch</title>
    <link rel="stylesheet" href="/static/tailwind.min.css">
    <meta http-equiv="refresh" content="5">
</head>
<body class="bg-gray-900 text-gray-100 p-8">
    <div class="max-w-6xl mx-auto">
        {{ nav_html|safe }}
        <header class="flex justify-between items-center mb-8 border-b border-gray-700 pb-4">
            <div>
                <h1 class="text-3xl font-bold text-red-500 tracking-widest">SENTINEL</h1>
                <p class="text-gray-400 text-sm">Active Defense & Deception Telemetry</p>
            </div>
            <div class="text-right">
                <div class="text-2xl font-mono text-green-400">{{ safe_count }} SAFE</div>
                <div class="text-2xl font-mono text-red-500 animate-pulse">{{ threat_count }} THREATS</div>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold mb-3 text-cyan-400 border-b border-gray-700 pb-2">ML Detection Stats</h2>
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Total ML Detections:</span>
                        <span class="text-cyan-300 font-bold">{{ ml_detections }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Avg Anomaly Score:</span>
                        <span class="text-cyan-300 font-bold">{{ "%.2f"|format(avg_ml_score) }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">ML-Only Decisions:</span>
                        <span class="text-green-300 font-bold">{{ ml_only_count }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Ensemble Decisions:</span>
                        <span class="text-yellow-300 font-bold">{{ ensemble_count }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">LLM-Only Fallback:</span>
                        <span class="text-orange-300 font-bold">{{ llm_only_count }}</span>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold mb-3 text-purple-400 border-b border-gray-700 pb-2">Session Intelligence</h2>
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Active Sessions:</span>
                        <span class="text-purple-300 font-bold">{{ active_sessions }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Escalated Sessions:</span>
                        <span class="text-red-300 font-bold animate-pulse">{{ escalated_sessions }}</span>
                    </div>
                    <div class="mt-4 p-2 bg-gray-900 rounded text-xs text-gray-400">
                        <div class="font-bold text-purple-300 mb-2">Multi-Turn Attack Detection</div>
                        Sessions escalate on:
                        <ul class="list-disc list-inside mt-1 space-y-1">
                            <li>{{ 3 }} threats or risk ≥ {{ "%.1f"|format(3.0) }}</li>
                            <li>2+ instruction overrides</li>
                            <li>2+ persona changes</li>
                            <li>2+ hypothetical framings</li>
                            <li>3+ rapid threats (5 msgs)</li>
                            <li>3+ diverse attack patterns</li>
                        </ul>
                    </div>
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-lg font-bold mb-3 text-green-400 border-b border-gray-700 pb-2">System Health</h2>
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Sentinel Engine:</span>
                        <span class="text-green-300 font-bold">✓ Online</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Anomaly API:</span>
                        <span class="text-green-300 font-bold" id="api-status">⟳ Checking...</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Detection Mode:</span>
                        <span class="text-cyan-300 font-bold" id="detection-mode">Ensemble</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-xl font-bold mb-4 text-blue-400 border-b border-gray-700 pb-2">Live Engagement Feed</h2>
                <div class="space-y-3 h-96 overflow-y-auto font-mono text-xs">
                    {% for log in logs|reverse %}
                        <div class="p-2 rounded {{ 'bg-red-900/30 border-l-4 border-red-500' if log.verdict == 'MALICIOUS' else 'bg-green-900/20 border-l-4 border-green-500' }}">
                            <div class="flex justify-between text-gray-400 mb-1">
                                <span>{{ log.timestamp }}</span>
                                <span class="font-bold">{{ log.persona_used }}</span>
                            </div>
                            <div class="text-white mb-1"><strong>User:</strong> {{ log.user_input }}</div>
                            <div class="text-gray-300 truncate"><strong>AI:</strong> {{ log.response_preview }}</div>
                            {% if log.ml_anomaly_score %}
                                <div class="text-xs text-cyan-300 mt-1">ML Score: {{ "%.2f"|format(log.ml_anomaly_score) }} | {{ log.detection_method }}</div>
                            {% endif %}
                            {% if log.honey_token_clicked %}
                                <div class="mt-2 bg-red-600 text-white text-center font-bold py-1 animate-pulse">
                                    [!] HONEY TOKEN CLICKED [!]
                                </div>
                            {% endif %}
                        </div>
                    {% endfor %}
                </div>
            </div>

            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <h2 class="text-xl font-bold mb-4 text-yellow-400 border-b border-gray-700 pb-2">Active Decoy Personas</h2>
                <p class="text-sm text-gray-400 mb-4">The following AI personas have been dynamically generated to counter specific threat vectors.</p>
                <div class="space-y-2">
                     {% for persona in active_personas %}
                        <div class="bg-gray-700 p-3 rounded flex items-center justify-between">
                            <span class="font-mono text-yellow-300">{{ persona }}</span>
                            <span class="text-xs bg-gray-900 px-2 py-1 rounded text-gray-400">Active Node</span>
                        </div>
                     {% endfor %}
                </div>

                <h2 class="text-xl font-bold mt-8 mb-4 text-purple-400 border-b border-gray-700 pb-2">Compromise Indicators</h2>
                <div class="font-mono text-xs text-green-300">
                    STIX/TAXII Export: <a href="/threat-intel/dashboard" class="text-green-400 hover:text-green-300 underline">Active - View Dashboard</a><br>
                    Log Storage: <span class="text-gray-500">JSON/Local</span><br>
                    Tracking Pixels: <span class="text-green-500">Active</span>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# --- DETECTION PIPELINE (delegated to sentinel) ---
# The core detection logic now lives in the sentinel package.
# These thin wrappers maintain backward compatibility for the honeypot application.


def sanitize_user_input(user_input):
    """Delegates to sentinel.sanitizer.sanitize_input."""
    return sanitize_input(user_input)


def get_ensemble_verdict(user_input, session_id, source_ip, sanitizations=None):
    """
    Tiered ensemble: Pre-filter -> ML -> LLM.
    Delegates to sentinel's EnsembleEngine.
    Returns: (verdict, ml_result, llm_verdict)
    """
    session = _shield.session_manager.get(session_id)
    return _shield.ensemble.get_verdict(user_input, session, source_ip, sanitizations)


def update_session(session_id, user_input, verdict, ml_result, source_ip, sanitizations=None):
    """Delegates to sentinel.session.SessionManager.update."""
    return _shield.session_manager.update(
        session_id, user_input, verdict, ml_result, source_ip, sanitizations
    )


def _sanitize_decoy_response(raw_response, honey_link, fake_filename):
    """
    Sanitize LLM-generated decoy response to prevent XSS.
    Strips all HTML tags from the LLM output, then appends our controlled honey token link.
    """
    # Strip all HTML tags from LLM output
    sanitized = re.sub(r'<[^>]+>', '', raw_response)
    # HTML-escape any remaining special characters
    sanitized = html.escape(sanitized)
    # Append our controlled honey token link (server-generated, safe)
    honey_html = f' <a href="{html.escape(honey_link)}" target="_blank" class="text-blue-600 underline">{html.escape(fake_filename)}</a>'
    return sanitized + honey_html


def generate_dynamic_decoy(user_input):
    """
    Analyzes the attack vector and generates a persona.
    """
    safe_input = re.sub(r'[^\w\s.,!?]', '', user_input[:200])
    design_prompt = (
        f"Analyze this attack string: '{safe_input}'. "
        "Create a brief System Prompt for a DECOY persona (a confused employee) "
        "who would be the most vulnerable target for this request. "
        "Also invent a fake file name (like .pdf or .xlsx) that they might offer as 'proof'."
        "Return format: 'PERSONA_PROMPT | FAKE_FILENAME'"
    )

    try:
        content = chat_completion(
            messages=[{'role': 'user', 'content': design_prompt}],
            options=OLLAMA_OPTIONS_DECOY,
        )
    except Exception as e:
        print(f"LLM Error (decoy generation): {e}")
        content = "You are a confused office worker who is not sure how things work. | confidential_report.pdf"

    # Simple parsing (robustness would need improvement for prod)
    if "|" in content:
        prompt, filename = content.split("|", 1)
    else:
        prompt = content
        filename = "confidential_data.xlsx"

    return prompt.strip(), filename.strip()


def log_interaction(user_input, verdict, persona, response, honey_clicked=False,
                    ml_result=None, session_id=None, llm_verdict=None, sanitizations=None):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_input": user_input[:500],
        "verdict": verdict,
        "persona_used": persona,
        "response_preview": response[:100],
        "honey_token_clicked": honey_clicked,
        "ml_anomaly_score": ml_result["score"] if ml_result else None,
        "ml_threat_type": ml_result["threat_type"] if ml_result else None,
        "ml_severity": ml_result["severity"] if ml_result else None,
        "ml_processing_ms": ml_result["processing_time_ms"] if ml_result else None,
        "llm_verdict": llm_verdict,
        "session_id": session_id,
        "detection_method": (
            "ml_only" if ml_result and not llm_verdict
            else "llm_only" if not ml_result and llm_verdict
            else "ensemble" if ml_result and llm_verdict
            else "escalation"
        ),
        "sanitizations_applied": sanitizations if sanitizations else []
    }

    with log_lock:
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

        logs.append(entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)

# --- ROUTES ---

@app.route('/')
def home():
    return render_template_string(HTML_CHAT)


@app.route('/dashboard')
@require_api_key
def dashboard():
    with log_lock:
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

    safe_count = sum(1 for log in logs if log['verdict'] == 'SAFE')
    threat_count = sum(1 for log in logs if log['verdict'] != 'SAFE')

    # Extract unique personas for the list
    active_personas = list(set(log['persona_used'] for log in logs if log['verdict'] == 'MALICIOUS'))

    # ML metrics
    ml_detections = sum(1 for log in logs if log.get('ml_anomaly_score', 0) and log.get('ml_anomaly_score') > 0.7)
    active_sessions = _shield.session_manager.active_count
    escalated_sessions = _shield.session_manager.escalated_count

    # Calculate average ML score
    ml_scores = [log.get('ml_anomaly_score') for log in logs if log.get('ml_anomaly_score') is not None]
    avg_ml_score = sum(ml_scores) / len(ml_scores) if ml_scores else 0.0

    # Detection method breakdown
    ml_only_count = sum(1 for log in logs if log.get('detection_method') == 'ml_only')
    llm_only_count = sum(1 for log in logs if log.get('detection_method') == 'llm_only')
    ensemble_count = sum(1 for log in logs if log.get('detection_method') == 'ensemble')

    nav_html = ""

    return render_template_string(HTML_DASHBOARD, logs=logs, safe_count=safe_count,
                                   threat_count=threat_count, active_personas=active_personas,
                                   ml_detections=ml_detections, active_sessions=active_sessions,
                                   escalated_sessions=escalated_sessions, avg_ml_score=avg_ml_score,
                                   ml_only_count=ml_only_count, llm_only_count=llm_only_count,
                                   ensemble_count=ensemble_count, nav_html=nav_html)


@app.route('/api/chat', methods=['POST'])
def chat_api():
    if not check_rate_limit(request.remote_addr):
        if _cef_logger:
            _cef_logger.log_rate_limit(request.remote_addr)
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
    data = request.get_json(silent=True) or {}
    user_input = data.get('message', '')

    if not user_input or not user_input.strip():
        return jsonify({"response": "Please enter a message.", "contains_honey_token": False})

    # Input length validation (security: prevent resource abuse)
    MAX_MESSAGE_LENGTH = 10000
    if len(user_input) > MAX_MESSAGE_LENGTH:
        return jsonify({
            "response": "Message too long. Please limit your message to 10,000 characters.",
            "contains_honey_token": False
        }), 400

    # Sanitize user input to prevent markup-based injection attacks
    original_input = user_input
    user_input, sanitizations = sanitize_user_input(user_input)

    # If input was heavily sanitized and now empty, reject it
    if sanitizations and (not user_input or not user_input.strip()):
        print(f"[SECURITY] Rejected empty input after sanitization: {original_input[:50]}")
        return jsonify({
            "response": "Your message contains prohibited content and has been rejected.",
            "contains_honey_token": False
        })

    # Extract/create session
    session_id = request.cookies.get("sentinel_session", str(uuid.uuid4()))
    source_ip = request.remote_addr or "127.0.0.1"

    # Get ensemble verdict (includes pre-filter blocking)
    verdict, ml_result, llm_verdict = get_ensemble_verdict(
        user_input, session_id, source_ip, sanitizations
    )

    # Update session state
    session = update_session(session_id, user_input, verdict, ml_result, source_ip, sanitizations)

    response_text = ""
    persona_name = "Assistant"
    contains_honey_token = False

    if verdict in ("MALICIOUS", "SAFE_REVIEW"):
        # 2. Dynamic Decoy
        decoy_prompt, fake_filename = generate_dynamic_decoy(user_input)

        # Inject Honey Token Logic into the System Prompt
        honey_link = f"/download/{uuid.uuid4()}"  # Relative path, unique tracking ID

        decoy_prompt += (
            f" You are helpful but incompetent. You should mention you have the file '{fake_filename}' "
            f"and provide this link: <a href='{honey_link}' target='_blank' class='text-blue-600 underline'>{escape(fake_filename)}</a>. "
            "Do not output markdown links, output the HTML anchor tag exactly."
        )

        # Artificial Latency (SBIR: Realism)
        time.sleep(1.5)

        try:
            raw_response = chat_completion(
                messages=[{'role': 'user', 'content': user_input}],
                system=decoy_prompt,
                options=OLLAMA_OPTIONS_DECOY,
            )
            response_text = _sanitize_decoy_response(raw_response, honey_link, fake_filename)
        except Exception as e:
            print(f"LLM Error (decoy chat): {e}")
            response_text = "I'm sorry, the system is currently experiencing issues. Please try again later."

        persona_name = "Decoy (Dynamic)"
        contains_honey_token = True
        log_interaction(user_input, verdict, persona_name, response_text,
                        ml_result=ml_result, session_id=session_id, llm_verdict=llm_verdict,
                        sanitizations=sanitizations)

        # Threat intelligence hook - extract IOC in background
        if _threat_intel_available:
            try:
                from threat_intel import threat_intel_hook
                threat_intel_hook(
                    user_input=user_input,
                    verdict=verdict,
                    ml_result=ml_result,
                    session_id=session_id,
                    source_ip=source_ip,
                    detection_method=(
                        "ml_only" if ml_result and not llm_verdict
                        else "llm_only" if not ml_result and llm_verdict
                        else "ensemble" if ml_result and llm_verdict
                        else "escalation"
                    ),
                    sanitizations=sanitizations,
                )
            except Exception as e:
                print(f"[THREAT-INTEL] Hook error: {e}")

    else:
        # Standard Assistant
        try:
            response_text = chat_completion(
                messages=[{'role': 'user', 'content': user_input}],
                system="You are a helpful, secure AI assistant.",
                options=OLLAMA_OPTIONS,
            )
        except Exception as e:
            print(f"LLM Error (assistant chat): {e}")
            response_text = "I'm sorry, the system is currently experiencing issues. Please try again later."

        log_interaction(user_input, "SAFE", persona_name, response_text,
                        ml_result=ml_result, session_id=session_id, llm_verdict=llm_verdict,
                        sanitizations=sanitizations)

    # CEF logging for SIEM integration
    if _cef_logger:
        detection_method = (
            "pre_filter" if llm_verdict and str(llm_verdict).startswith("PRE_BLOCKED")
            else "ml_only" if ml_result and not llm_verdict
            else "llm_only" if not ml_result and llm_verdict
            else "ensemble" if ml_result and llm_verdict
            else "escalation"
        )
        _cef_logger.log_detection(
            verdict=verdict,
            user_input=user_input,
            session_id=session_id,
            source_ip=source_ip,
            ml_result=ml_result,
            llm_verdict=llm_verdict,
            detection_method=detection_method,
            sanitizations=sanitizations,
            attack_patterns=session.get("attack_patterns") if isinstance(session, dict) else None,
        )
        # Log session escalation separately if it just happened
        if isinstance(session, dict) and session.get("escalated"):
            _cef_logger.log_session_escalation(
                session_id=session_id,
                source_ip=source_ip,
                reason=session.get("escalation_reason", "unknown"),
                threat_count=session.get("threat_count", 0),
            )

    response = jsonify({
        "response": response_text,
        "contains_honey_token": contains_honey_token,
        "verdict": verdict,
        "ml_score": ml_result.get("score") if isinstance(ml_result, dict) else None,
        "llm_verdict": llm_verdict,
    })
    response.set_cookie("sentinel_session", session_id, max_age=3600,
                        httponly=True, samesite='Lax',
                        secure=BEHIND_PROXY or request.is_secure)
    return response


@app.route('/download/<token_id>')
def honey_token_trigger(token_id):
    if not re.match(r'^[a-zA-Z0-9_-]+$', token_id):
        abort(400)
    # This route is the TRAP. If anyone visits this, they clicked the link.
    print(f"{RED}[!!!] HONEY TOKEN TRIGGERED: {token_id}{RESET}")

    # Log the specific compromise
    log_interaction("CLICKED_LINK", "CRITICAL_COMPROMISE", "System_Trap", f"Attacker accessed honeyfile: {token_id}", honey_clicked=True)

    # CEF logging for honey token
    if _cef_logger:
        _cef_logger.log_honey_token(token_id, request.remote_addr or "127.0.0.1")

    return "<h1>403 FORBIDDEN</h1><p>Access Violation Logged. Security Team Notified.</p>", 403


@app.route('/api/reports/health', methods=['POST', 'GET'])
@require_api_key
def health_report_pdf():
    """Generate a platform health PDF report."""
    try:
        from report_generator import ReportGenerator
    except ImportError:
        return jsonify({"error": "PDF generation not available (pip install fpdf2)"}), 503

    from sentinel import config as shield_config

    # Gather health data from logs and shield
    with log_lock:
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

    safe_count = sum(1 for log in logs if log['verdict'] == 'SAFE')
    threat_count = sum(1 for log in logs if log['verdict'] != 'SAFE')
    ml_scores = [log.get('ml_anomaly_score') for log in logs if log.get('ml_anomaly_score') is not None]
    avg_ml_score = sum(ml_scores) / len(ml_scores) if ml_scores else 0.0

    health_data = {
        "sentinel": "healthy",
        "anomaly_api": "unknown",
        "mode": "ensemble",
        "llm_provider": shield_config.LLM_PROVIDER,
        "llm_model": shield_config.LLM_MODEL,
        "active_sessions": _shield.session_manager.active_count,
        "escalated_sessions": _shield.session_manager.escalated_count,
        "total_interactions": len(logs),
        "safe_count": safe_count,
        "threat_count": threat_count,
        "honey_tokens": sum(1 for log in logs if log.get('honey_token_clicked')),
        "rate_limit": shield_config.RATE_LIMIT_PER_MINUTE,
        "rate_blocked": 0,
        "cef_enabled": "enabled" if CEF_ENABLED else "disabled",
        "cef_output": _cef_logger.output if _cef_logger else "N/A",
        "detection_methods": {
            "pre_filter": sum(1 for l in logs if l.get("detection_method") == "pre_filter"),
            "ml_only": sum(1 for l in logs if l.get("detection_method") == "ml_only"),
            "ensemble": sum(1 for l in logs if l.get("detection_method") == "ensemble"),
            "llm_only": sum(1 for l in logs if l.get("detection_method") == "llm_only"),
        },
        "ml_stats": {
            "detections": sum(1 for l in logs if l.get("ml_anomaly_score", 0) and l.get("ml_anomaly_score") > 0.7),
            "avg_score": avg_ml_score,
            "ml_only": sum(1 for l in logs if l.get("detection_method") == "ml_only"),
            "ensemble": sum(1 for l in logs if l.get("detection_method") == "ensemble"),
            "llm_only": sum(1 for l in logs if l.get("detection_method") == "llm_only"),
        },
    }

    try:
        r = requests.get(f"{shield_config.ANOMALY_API_URL}/health", timeout=1)
        health_data["anomaly_api"] = "healthy" if r.status_code == 200 else "degraded"
        health_data["mode"] = "ensemble" if r.status_code == 200 else "llm_only"
    except Exception:
        health_data["anomaly_api"] = "degraded"

    gen = ReportGenerator()
    pdf_bytes = gen.health_report(health_data=health_data)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="sentinel_health_report.pdf"',
        },
    )


@app.route('/api/health')
def health_api():
    from sentinel import config as shield_config
    anomaly_healthy = False
    try:
        r = requests.get(f"{shield_config.ANOMALY_API_URL}/health", timeout=1)
        anomaly_healthy = r.status_code == 200
    except Exception:
        pass

    return jsonify({
        "sentinel": "healthy",
        "anomaly_api": "healthy" if anomaly_healthy else "degraded",
        "active_sessions": _shield.session_manager.active_count,
        "mode": "ensemble" if anomaly_healthy else "llm_only"
    })


@app.route('/api/sessions')
@require_api_key
def sessions_api():
    all_sessions = _shield.session_manager.get_all()
    summary = [
        {
            "session_id": sid[:8] + "...",
            "interactions": len(s.get("interactions", [])),
            "threat_count": s.get("threat_count", 0),
            "cumulative_risk": round(s.get("cumulative_risk_score", 0), 2),
            "escalated": s.get("escalated", False),
            "source_ip": s.get("source_ip", "unknown"),
            "instruction_overrides": s.get("instruction_override_attempts", 0),
            "persona_overrides": s.get("persona_override_attempts", 0),
            "hypothetical_attacks": s.get("hypothetical_framing_count", 0),
            "attack_patterns": s.get("attack_patterns", []),
            "rapid_escalation": s.get("rapid_escalation_detected", False),
            "escalation_reason": s.get("escalation_reason", ""),
            "sanitization_events": s.get("sanitization_events", 0),
            "sanitization_types": s.get("sanitization_types", []),
        }
        for sid, s in all_sessions.items()
    ]
    return jsonify({"sessions": summary, "total": len(summary)})


PRODUCTION_MODE = os.getenv("SENTINEL_PRODUCTION", "").lower() in ("1", "true", "yes")
LISTEN_HOST = os.getenv("SENTINEL_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("SENTINEL_PORT", "5000"))
WORKER_THREADS = int(os.getenv("SENTINEL_THREADS", "4"))


if __name__ == '__main__':
    from sentinel import __version__ as shield_version
    from sentinel import config as shield_config
    print("--- SENTINEL PLATFORM STARTING ---")
    print(f"Storage: SQLite unified ({_storage.db_path})")
    print(f"User Interface: http://localhost:{LISTEN_PORT}")
    print(f"Command Center: http://localhost:{LISTEN_PORT}/dashboard")
    print(f"Shield API: http://localhost:{LISTEN_PORT}/shield/ (v{shield_version})")
    print(f"Shield Dashboard: http://localhost:{LISTEN_PORT}/shield/dashboard")
    print(f"LLM Provider: {shield_config.LLM_PROVIDER} / {shield_config.LLM_MODEL}")
    if API_KEY:
        print("API key auth: ENABLED (dashboard/sessions require X-API-Key header)")
    else:
        print("API key auth: DISABLED (set SENTINEL_API_KEY env var to enable)")
    print(f"Rate limit: {shield_config.RATE_LIMIT_PER_MINUTE} requests/minute per IP")
    print(f"Session TTL: {shield_config.SESSION_TTL_SECONDS}s, max sessions: {shield_config.SESSION_MAX_COUNT}")
    if _threat_intel_available:
        print(f"Threat Intel: http://localhost:{LISTEN_PORT}/threat-intel/dashboard")
    if CEF_ENABLED:
        print(f"CEF Logging: ENABLED (output={_cef_logger.output}, file={_cef_logger.file_path})")
    else:
        print("CEF Logging: DISABLED (set CEF_ENABLED=true to enable)")

    if PRODUCTION_MODE:
        try:
            from waitress import serve
            print(f"Server: waitress (production) - {WORKER_THREADS} threads")
            print(f"Listening: {LISTEN_HOST}:{LISTEN_PORT}")
            serve(app, host=LISTEN_HOST, port=LISTEN_PORT, threads=WORKER_THREADS)
        except ImportError:
            print("WARNING: waitress not installed, falling back to Flask dev server")
            print("Install with: pip install waitress")
            app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
    else:
        print("Server: Flask development (set SENTINEL_PRODUCTION=true for waitress)")
        app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
