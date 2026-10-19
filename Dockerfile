FROM python:3.12-alpine
WORKDIR /app
COPY probe24.py /app/probe24.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe24.py"]
