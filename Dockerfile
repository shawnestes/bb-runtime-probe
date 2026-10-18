FROM python:3.12-alpine
WORKDIR /app
COPY probe3.py /app/probe3.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe3.py"]
