# syntax=docker/dockerfile:1

# ---------- Stage 1: build the virtualenv ----------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# No PyTorch: models run through ONNX Runtime (see app/core/onnx_models.py).
COPY requirements.txt .
RUN pip install -r requirements.txt \
 && python -m spacy download en_core_web_sm

# Strip files that are never used at runtime.
RUN pip uninstall -y pip setuptools wheel \
 && find /opt/venv -depth -type d -name "__pycache__" -exec rm -rf {} + \
 && find /opt/venv/lib/python3.12/site-packages -depth -type d -name "tests" -exec rm -rf {} + \
 && find /opt/venv -name "*.a" -delete \
 && python -c "import importlib.util as u, sys; sys.exit(u.find_spec('torch') is not None)"

# ---------- Stage 2: minimal runtime ----------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    HF_HOME=/home/app/.cache/huggingface \
    HF_HUB_DISABLE_TELEMETRY=1

# Pre-create the model cache dir so a mounted volume inherits app ownership
# (otherwise Docker creates it as root and model downloads fail with EACCES).
RUN useradd --create-home --uid 1000 app \
 && mkdir -p /home/app/.cache/huggingface \
 && chown -R app:app /home/app/.cache

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app app ./app

USER app
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
