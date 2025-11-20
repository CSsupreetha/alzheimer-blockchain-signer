# (keep the rest of your Dockerfile as-is)
# At the end, replace CMD with the following:

# Ensure PORT env var is honored by gunicorn
ENV PORT 8000

# Start gunicorn using the runtime PORT value provided by Railway
CMD ["sh", "-c", "exec gunicorn signer:app --bind 0.0.0.0:${PORT} --workers 2 --timeout 120"]
