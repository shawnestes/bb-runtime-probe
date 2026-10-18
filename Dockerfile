FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir paramiko 2>&1 | tail -2
COPY probe13.py /app/probe13.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe13.py"]
