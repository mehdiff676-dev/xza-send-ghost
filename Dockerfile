FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1
ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 15028

CMD ["python", "app.py"]