FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# 1. Pre-install CPU-only PyTorch (prevents pip from downloading ~6GB of NVIDIA/CUDA packages)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# 2. Install remaining requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && python -m spacy download en_core_web_sm

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
