FROM python:3.12-alpine
WORKDIR /app
COPY probe16.py /app/probe16.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe16.py"]
