FROM python:3.12-alpine
WORKDIR /app
COPY buildprobe.py /app/buildprobe.py
RUN python3 /app/buildprobe.py > /app/build_facts.txt 2>&1 || true
COPY probe5.py /app/probe5.py
EXPOSE 8080
CMD ["python3", "-u", "/app/probe5.py"]
