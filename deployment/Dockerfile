# Guardrail Dockerfile
# Multi-stage build for production deployment

# Stage 1: Build dependencies
FROM python:3.12-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY pyproject.toml ./
COPY README.md ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

# Stage 2: Runtime
FROM python:3.12-slim as runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libffi8 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r guardrail && useradd -r -g guardrail -d /app -s /bin/bash guardrail

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY docs/ ./docs/
COPY examples/ ./examples/

# Create necessary directories
RUN mkdir -p /var/log/guardrail /var/lib/guardrail/lsfs /tmp/guardrail_firecracker /tmp/guardrail_audit.log \
    && chown -R guardrail:guardrail /app /var/log/guardrail /var/lib/guardrail /tmp/guardrail_firecracker /tmp/guardrail_audit.log

# Switch to non-root user
USER guardrail

# Environment variables
ENV PYTHONPATH=/app/src \
    GUARDRAIL_AUDIT_LOG_PATH=/tmp/guardrail_audit.log \
    GUARDRAIL_LSFS_ROOT=/var/lib/guardrail/lsfs \
    PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090

# Default command
CMD ["python", "-m", "guardrail.server"]