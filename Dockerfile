FROM python:3.12-alpine
WORKDIR /app
COPY probe23.py /app/probe23.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe23.py"]
