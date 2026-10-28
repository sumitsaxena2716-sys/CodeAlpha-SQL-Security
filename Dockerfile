
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements-lock.txt ./requirements-lock.txt

RUN python -m pip install \
    --only-binary=:all: \
    --no-cache-dir \
    --require-hashes \
    -r requirements-lock.txt \
    && useradd --create-home --shell /usr/sbin/nologin appuser

COPY app.py database.py generate_key.py ./
COPY templates ./templates
COPY static ./static

RUN mkdir -p /app/logs \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:5000", "app:app"]
