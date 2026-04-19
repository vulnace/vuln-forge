FROM vuln-forge:latest

WORKDIR /app

ENV PIP_ROOT_USER_ACTION=ignore
ENV DEBIAN_FRONTEND=noninteractive

# Clear parent ENTRYPOINT
ENTRYPOINT []

# WeasyPrint system dependencies
RUN apt-get update && apt-get install -y \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install web dependencies
RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    websockets \
    jinja2 \
    python-multipart \
    weasyprint \
    aiofiles

# Fix data directory permissions
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8000

CMD ["python3", "-u", "-m", "uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000"]