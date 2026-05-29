FROM python:3.11-slim

WORKDIR /app

# whois binary used as fallback when python-whois fails
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_DEBUG=false
ENV PORT=5000

# Use gunicorn for production; 2 workers is enough for a single-node demo
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
