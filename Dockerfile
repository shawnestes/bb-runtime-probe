FROM python:3.12-alpine
WORKDIR /app
COPY probe14.py /app/probe14.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe14.py"]
