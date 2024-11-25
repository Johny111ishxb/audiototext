FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    libsndfile1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Environment variables
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_TIMEOUT=300
ENV GUNICORN_WORKERS=1
ENV GUNICORN_THREADS=2  # Reduced threads for lower memory consumption

# Expose the port the app runs on
EXPOSE 8000

# Use Gunicorn with optimized settings
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--timeout", "300", "--workers", "1", "--threads", "2", "app:app"]
