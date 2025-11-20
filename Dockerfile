# Railway signer microservice Dockerfile (single-stage, minimal)
FROM python:3.10-slim

WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose port (informational)
EXPOSE 8000

# Default PORT env var (Railway will override at runtime)
ENV PORT=8000

# Start gunicorn honoring the runtime $PORT provided by Railway
# Use sh -c so the shell expands ${PORT}
CMD ["sh", "-c", "exec gunicorn signer:app --bind 0.0.0.0:${PORT} --workers 2 --timeout 120"]
