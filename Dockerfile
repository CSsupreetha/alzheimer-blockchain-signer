# Dockerfile -- single-stage, bullet-proof for Flask + Gunicorn apps

FROM python:3.11-slim

# Prevent Python from creating .pyc files and to buffer logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Ensure PORT env var is visible to process and runtime (Railway sets PORT)
ENV PORT=8000

# Create app dir
WORKDIR /app

# System deps (add extras if you need e.g. libpq-dev)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy project files
COPY . /app

# Ensure gunicorn is available (should be in requirements.txt)
# Default command: gunicorn will bind to 0.0.0.0:$PORT
# Replace `app:app` with your Flask entrypoint module:variable if different
CMD ["gunicorn", "--bind", "0.0.0.0:${PORT}", "app:app", "--workers", "2", "--threads", "2", "--timeout", "120"]
