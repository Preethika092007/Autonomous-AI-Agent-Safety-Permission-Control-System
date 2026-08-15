FROM python:3.11-slim

# Create a non-root user
RUN addgroup --system appgroup && adduser --system --group appuser

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Change ownership of the app directory
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

EXPOSE 8000

# Start without reload in production-ready setup
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
