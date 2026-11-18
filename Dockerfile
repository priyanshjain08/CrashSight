# UNVERIFIED: Docker was not available where this was written; this image has never been built.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/crashsight_server backend/crashsight_server
COPY dashboard dashboard
ENV PYTHONPATH=/app/backend CRASHSIGHT_HOST=0.0.0.0 CRASHSIGHT_DATA_DIR=/data
VOLUME /data
USER nobody
HEALTHCHECK CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health')"
CMD ["python3", "-m", "crashsight_server.server"]
