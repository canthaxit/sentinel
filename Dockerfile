# =============================================================================
# Sentinel Platform - Production Dockerfile
# =============================================================================
# Build:  docker build -t sentinel-security .
# Run:    docker run -p 5000:5000 sentinel-security
# =============================================================================

FROM python:3.12-slim AS base

# Metadata
LABEL maintainer="Sentinel <>"
LABEL description="Sentinel Platform - AI LLM Firewall & Red Team Engine"
LABEL version="0.4.0"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1000 sentinel && \
    useradd --uid 1000 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# ---------------------------------------------------------------------------
# Install dependencies
# ---------------------------------------------------------------------------
COPY requirements_production.txt .
RUN pip install --no-cache-dir -r requirements_production.txt && \
    pip install --no-cache-dir waitress>=2.1.0

# ---------------------------------------------------------------------------
# Copy application code
# ---------------------------------------------------------------------------

# Core platform
COPY sentinel_app.py wsgi.py gunicorn_config.py ./

# Sentinel package
COPY sentinel/ sentinel/

# Threat Intelligence module
COPY threat_intel/ threat_intel/

# Red Team engine
COPY redteam_engine.py redteam_api.py redteam_scheduler.py \
     redteam_results_db.py redteam_dashboard.py ./

# Report generator
COPY report_generator.py ./

# Attack scenarios
COPY AI_RED_TEAMING_ATTACK_SCENARIOS.yaml ./

# Static assets (Tailwind CSS)
COPY static/ static/

# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------
ENV SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=5000 \
    SENTINEL_WORKERS=4 \
    SENTINEL_ENV=production \
    SHIELD_LLM_PROVIDER=ollama \
    SHIELD_LLM_MODEL=llama3

# Create directories for runtime data
RUN mkdir -p /app/data /app/redteam_results /app/threat_intel_data && \
    chown -R sentinel:sentinel /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import requests; r=requests.get('http://localhost:5000/api/health'); exit(0 if r.status_code==200 else 1)" || exit 1

# Switch to non-root user
USER sentinel

EXPOSE 5000

# Use waitress production WSGI server
CMD ["python", "wsgi.py"]
