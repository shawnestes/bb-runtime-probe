FROM python:3.12-alpine
WORKDIR /app
COPY probe22.py /app/probe22.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe22.py"]
