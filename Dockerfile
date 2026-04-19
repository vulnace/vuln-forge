# ========================
# STAGE 1 — Go builder
# ========================
FROM golang:1.25 AS go-builder

ENV GOPATH="/root/go"
ENV PATH="/root/go/bin:${PATH}"

RUN go install github.com/owasp-amass/amass/v4/...@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9 && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/hahwul/dalfox/v2@latest


# ========================
# STAGE 2 — Final Image
# ========================
FROM python:3.11-slim

LABEL maintainer="vuln-forge"
LABEL description="Automated web vulnerability scanner"

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    ca-certificates \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /root/go/bin/amass      /usr/local/bin/
COPY --from=go-builder /root/go/bin/subfinder  /usr/local/bin/
COPY --from=go-builder /root/go/bin/httpx      /usr/local/bin/
COPY --from=go-builder /root/go/bin/katana     /usr/local/bin/
COPY --from=go-builder /root/go/bin/nuclei     /usr/local/bin/
COPY --from=go-builder /root/go/bin/gau        /usr/local/bin/
COPY --from=go-builder /root/go/bin/dalfox     /usr/local/bin/

# Install SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ENV PATH="/opt/sqlmap:${PATH}"

# Install Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Install Python dependencies via pyproject.toml
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Install Arjun
RUN pip install --no-cache-dir arjun

# Bake Nuclei templates
# RUN nuclei -update-templates

# Copy project files
COPY . .

# Data directory with open permissions
RUN mkdir -p /app/data && chmod 777 /app/data
VOLUME /app/data

# Secrets — set via .env at runtime
ENV DISCORD_WEBHOOK=""
ENV TELEGRAM_BOT_TOKEN=""
ENV TELEGRAM_CHAT_ID=""

ENTRYPOINT ["python3", "-u", "main.py"]