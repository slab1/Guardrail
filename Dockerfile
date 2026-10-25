# =========================================================
# Stage 1: Build Frontend Static Assets (Vite + React)
# =========================================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.node.json vite.config.ts postcss.config.js tailwind.config.js index.html ./
COPY src ./src

RUN npm run build

# =========================================================
# Stage 2: Production Python Kernel Engine (FastAPI + Z3)
# =========================================================
FROM python:3.10-slim AS runner
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8888

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt uvicorn

COPY app.py requirements.txt ./
COPY src ./src
COPY data ./data
COPY firebase-applet-config.json firebase-blueprint.json firestore.rules ./

# Copy compiled static frontend build
COPY --from=frontend-builder /app/dist ./dist

EXPOSE 8888

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8888/api/kernel/state || exit 1

CMD ["python3", "app.py"]
