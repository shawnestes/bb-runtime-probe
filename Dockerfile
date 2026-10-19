FROM python:3.12-alpine
WORKDIR /app
COPY probe20.py /app/probe20.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe20.py"]
