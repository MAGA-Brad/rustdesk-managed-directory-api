FROM python:3.13-slim

WORKDIR /app

COPY requirements.in .
RUN pip install --no-cache-dir -r requirements.in

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "21120"]
