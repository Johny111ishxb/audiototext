# Use slim base image
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ffmpeg \
    libsndfile1 \
    build-essential \
    python3-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first
COPY requirements.txt .

# Install Python packages with minimal dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set aggressive memory optimization environment variables
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
ENV PYTORCH_CPU_ALLOC_CONF=max_split_size_mb:32
ENV TORCH_CPU_ALLOC_CONF=max_split_size_mb:32
ENV TRANSFORMERS_OFFLINE=1
ENV TORCH_DISABLE_JIT=1

# Expose port
EXPOSE 8000

# Run with optimized settings
CMD ["sh", "-c", "gunicorn \
    --bind 0.0.0.0:$PORT \
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
    --preload \
    app:app"]
