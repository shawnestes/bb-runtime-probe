FROM python:3.12-alpine
WORKDIR /app
COPY probe33.py /app/probe33.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe33.py"]
