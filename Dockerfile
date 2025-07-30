FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN mkdir -p /config /logs

RUN pip install -r requirements.txt

EXPOSE 7952

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7952"]