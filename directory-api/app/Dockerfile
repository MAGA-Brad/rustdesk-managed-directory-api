# Pinned base image digest. Move it on purpose, like the pins in requirements.txt: pull the new
# python:3.13-slim, take its digest from `docker image inspect python:3.13-slim`, and rebuild.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "21120"]
