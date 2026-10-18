FROM python:3.12-alpine
WORKDIR /app
COPY probe.py /app/probe.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe.py"]
