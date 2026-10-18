FROM python:3.12-alpine
WORKDIR /app
COPY probe17.py /app/probe17.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe17.py"]
