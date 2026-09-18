FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install runtime system packages:
# - curl: required for Docker container HEALTHCHECK
# - nmap: required for deep-scan network and service discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user and directory for persistent SQLite data
RUN useradd -m -u 1000 drishti && \
    mkdir -p /app/data && \
    chown -R drishti:drishti /app

# Install Python dependencies first for optimal Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server application files
COPY --chown=drishti:drishti . .

# Ensure data directory exists and is writable by drishti user
RUN mkdir -p /app/data && chown -R drishti:drishti /app/data

USER drishti

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
