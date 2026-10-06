# SecureCodeGuard – Container Specification
FROM python:3.11-slim

LABEL maintainer="Tejas Parkar <123B1D063@pccoe.edu>"
LABEL description="SecureCodeGuard: AI-Assisted Secure Code Debugging & Review Assistant"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8501

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and synthetic datasets
COPY . .

# Create persistent storage directories
RUN mkdir -p /app/data /app/chroma_db /app/reports

EXPOSE 8501 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command runs the Streamlit UI
CMD ["streamlit", "run", "ui/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
