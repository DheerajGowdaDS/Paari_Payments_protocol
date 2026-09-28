FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY schemas/ ./schemas/
COPY sdk/ ./sdk/
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY README.md ./

RUN adduser --disabled-password --gecos "" paari
USER paari

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]