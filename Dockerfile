FROM python:3.12-alpine
WORKDIR /app
COPY buildprobe.py /app/buildprobe.py
RUN python3 /app/buildprobe.py > /app/build_facts.txt 2>&1 || true
COPY probe9.py /app/probe9.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe9.py"]
