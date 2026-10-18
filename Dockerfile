FROM python:3.12-alpine
WORKDIR /app
COPY probe4.py /app/probe4.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe4.py"]
