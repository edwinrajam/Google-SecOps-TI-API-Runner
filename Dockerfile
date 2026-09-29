FROM python:3.11-slim

WORKDIR /app

# Create non-root user for Cloud Run defense-in-depth
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code & static catalogs ONLY (never local DBs or keys)
COPY app.py .
RUN mkdir -p /app/data && chmod 700 /app/data
COPY data/catalog.json /app/data/catalog.json
COPY data/gti_catalog.json /app/data/gti_catalog.json
COPY static/ ./static/

# Ensure non-root ownership
RUN chown -R appuser:appuser /app

USER appuser

# Cloud Run automatically injects PORT and K_SERVICE
ENV PORT=8080
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["python3", "app.py"]
