FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --trusted-host dtpheva01.ap.denso.com -i http://dtpheva01.ap.denso.com/devpi/root/pypi/+simple/ -r requirements.txt

EXPOSE 7952

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7952"]