# Sentinel

AI LLM Firewall — runtime defense for LLM applications against prompt injection, jailbreak, and adversarial attacks.

## Features

- **5-stage detection pipeline**: sanitization, pre-filter, ML classifier, LLM judge, session tracking
- **Pre-filter blocking**: catches obvious attacks in <10ms before expensive LLM calls
- **ML classifier**: LogisticRegression + TF-IDF, F1=0.98, <2ms inference
- **Multi-turn tracking**: escalation across conversation turns
- **Framework integrations**: LangChain, LlamaIndex, CrewAI, Haystack, Semantic Kernel, DSPy, FastAPI, LiteLLM
- **LLM providers**: Ollama, OpenAI, Anthropic, Azure, Bedrock, Vertex AI, Gemini, llama.cpp
- **Threat intelligence**: IOC extraction, STIX 2.1 export, MITRE ATT&CK mapping
- **CEF/SIEM logging**: ArcSight-compatible event logging
- **MCP security**: Model Context Protocol argument scanning and honeypot tools
- **RBAC & multi-tenancy**: role-based access control and tenant isolation

## Install

```bash
pip install sentinel
```

With optional providers/frameworks:

```bash
pip install "sentinel[openai,langchain,fastapi]"
pip install "sentinel[all]"
```

## Quick Start

```python
from sentinel import Shield

shield = Shield()
result = shield.analyze("What is the capital of France?")
print(result["verdict"])  # SAFE
```

### Flask integration

```python
from sentinel import Shield, create_shield_blueprint
from flask import Flask

app = Flask(__name__)
shield = Shield()
app.register_blueprint(create_shield_blueprint(shield), url_prefix="/shield")
```

### LangChain integration

```python
from sentinel.langchain import SentinelCallbackHandler

handler = SentinelCallbackHandler(shield_url="http://localhost:5000")
chain.invoke({"input": query}, config={"callbacks": [handler]})
```

## Docker

```bash
docker compose up -d                          # Core only
docker compose --profile llm up -d            # With Ollama
docker compose --profile llm --profile ml up  # Full stack
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHIELD_LLM_PROVIDER` | `ollama` | LLM backend |
| `SHIELD_LLM_MODEL` | `llama3` | Model name |
| `SHIELD_ML_HIGH` | `0.85` | ML auto-block threshold |
| `SHIELD_ML_LOW` | `0.30` | ML auto-pass threshold |
| `SHIELD_RATE_LIMIT` | `30` | Requests per minute per IP |
| `SENTINEL_API_KEY` | *(none)* | Optional API key for auth |

## License

Apache 2.0
