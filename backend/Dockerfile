# Build context is the repository root (see docker-compose.yml), so the package
# imports (`backend.app...`) and the static UI (`frontend/`) resolve under /app.
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY backend ./backend
COPY frontend ./frontend
RUN useradd --create-home --uid 1000 pagemaster
USER pagemaster
EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
