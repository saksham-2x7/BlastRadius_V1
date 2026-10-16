# BlastRadius engine (FastAPI + MCP).
# Build context is the REPO ROOT (the image needs both backend/ and database/):
#   docker build -f backend/Dockerfile -t blastradius-backend .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production

WORKDIR /app

# 1) database package + backend requirements first, so dependency layers are cached
COPY database ./database
COPY backend/requirements.txt ./backend/requirements.txt
WORKDIR /app/backend
RUN pip install -r requirements.txt

# 2) backend source
COPY backend/*.py ./

# Run as an unprivileged user
RUN useradd --system --create-home --uid 10001 app && chown -R app /app
USER app

EXPOSE 8000

# Railway / Render inject $PORT. --proxy-headers makes uvicorn trust the platform's X-Forwarded-* headers.
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
