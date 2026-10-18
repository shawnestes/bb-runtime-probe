FROM python:3.12-alpine
WORKDIR /app
COPY probe15.py /app/probe15.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe15.py"]
