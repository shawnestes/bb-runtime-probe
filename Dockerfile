FROM python:3.12-alpine
WORKDIR /app
COPY probe32.py /app/probe32.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe32.py"]
