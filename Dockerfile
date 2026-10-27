# =========================================================
# Stage 1: Build Frontend Static Assets (Vite + React)
# =========================================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app

COPY package.json package-lock.json ./
COPY firebase-applet-config.json firebase-blueprint.json ./
RUN npm ci

COPY tsconfig.json tsconfig.node.json vite.config.ts postcss.config.js tailwind.config.js index.html ./
COPY src ./src
RUN npm run build

# =========================================================
# Stage 2: Build Native Rust PEP Engine & Run Security Invariant Tests
# =========================================================
FROM rust:1.80-slim AS rust-builder
WORKDIR /app

COPY . .
# Compile the native Tier-2 Data Plane PEP daemon with release optimizations
RUN cargo build --release && \
    cp target/release/guardrail-pep-daemon /app/guardrail-pep-daemon && \
    GUARDRAIL_PEP_SECRET="ci_pipeline_secure_random_key_987654321" PEP_SELF_TEST_ONLY="1" /app/guardrail-pep-daemon


# =========================================================
# Stage 3: Production Python Kernel Engine (FastAPI + Z3 + Native PEP)
# =========================================================
FROM python:3.10-slim AS runner
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8888 \
    GUARDRAIL_ENV=production

# Install system dependencies including libseccomp
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt uvicorn

COPY app.py requirements.txt ./
COPY src ./src
COPY data ./data
COPY firebase-applet-config.json firebase-blueprint.json firestore.rules ./

# Copy compiled static frontend build
COPY --from=frontend-builder /app/dist ./dist

# Copy verified native PEP binary
COPY --from=rust-builder /app/guardrail-pep-daemon /usr/local/bin/guardrail-pep-daemon

EXPOSE 8888

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8888/api/kernel/state || exit 1

CMD ["sh", "-c", "\
  if [ -z \"$GUARDRAIL_PEP_SECRET\" ]; then \
    echo 'FATAL: GUARDRAIL_PEP_SECRET environment variable is required in production'; \
    exit 1; \
  fi; \
  case \"$GUARDRAIL_PEP_SECRET\" in \
    default_secret_1234567890|test_secret*|changeme*) \
      echo 'FATAL: GUARDRAIL_PEP_SECRET is set to a known insecure default value'; \
      exit 1; \
      ;; \
  esac; \
  /usr/local/bin/guardrail-pep-daemon & \
  exec python3 app.py \
"]