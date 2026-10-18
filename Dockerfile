FROM python:3.12-alpine
WORKDIR /app
COPY probe19.py /app/probe19.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe19.py"]
