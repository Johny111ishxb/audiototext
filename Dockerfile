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

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_TIMEOUT=300
ENV GUNICORN_WORKERS=1
ENV GUNICORN_THREADS=4

# Expose the port the app runs on
EXPOSE 8000

# Use gunicorn with optimized settings
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --timeout $GUNICORN_TIMEOUT --workers $GUNICORN_WORKERS --threads $GUNICORN_THREADS --log-level info app:app"]
