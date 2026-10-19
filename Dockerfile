FROM python:3.12-alpine
WORKDIR /app
COPY probe21.py /app/probe21.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe21.py"]
