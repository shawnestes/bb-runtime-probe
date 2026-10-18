FROM python:3.12-alpine
WORKDIR /app
COPY probe18.py /app/probe18.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe18.py"]
