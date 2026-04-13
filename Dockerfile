FROM python:3.12-slim
WORKDIR /app
COPY mullvad-check.py .
COPY config.example.json .
RUN mkdir -p /data
VOLUME /data
ENTRYPOINT ["python3", "mullvad-check.py", "--output-dir", "/data"]
