# Use slim base image to reduce memory footprint
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

# Install Python packages with minimal dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables for memory optimization
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV GUNICORN_TIMEOUT=300
ENV GUNICORN_WORKERS=1
ENV GUNICORN_THREADS=1
ENV PYTORCH_NO_CUDA=1
ENV OMP_NUM_THREADS=1
ENV MKL_NUM_THREADS=1
ENV MALLOC_TRIM_THRESHOLD_=100000
ENV PYTHONMALLOC=malloc
ENV PYTORCH_CPU_ALLOC_CONF=max_split_size_mb:64

# Expose the port the app runs on
EXPOSE 8000

# Use gunicorn with memory-optimized settings
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT \
    --timeout $GUNICORN_TIMEOUT \
    --workers $GUNICORN_WORKERS \
    --threads $GUNICORN_THREADS \
    --worker-class=sync \
    --worker-tmp-dir=/dev/shm \
    --log-level info \
    --max-requests 1 \
    --max-requests-jitter 0 \
    --limit-request-line 0 \
    --limit-request-fields 0 \
    app:app"]
