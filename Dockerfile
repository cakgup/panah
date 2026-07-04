# syntax=docker/dockerfile:1.7
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/usr/local/bin:${PATH}

WORKDIR /app

SHELL ["/bin/bash", "-lc"]

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        ca-certificates \
        cron \
        curl \
        dnsutils \
        file \
        git \
        iputils-ping \
        jq \
        netcat-openbsd \
        openssl \
        openssh-client \
        python3 \
        python3-pip \
        socat \
        tcpdump \
        unzip \
        wget

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        masscan \
        ffuf \
        gobuster \
        amass \
        dnsrecon \
        fierce \
        nikto \
        sqlmap \
        whatweb \
        wpscan

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        hydra \
        medusa \
        john \
        hashcat \
        ncrack \
        patator \
        proxychains4 \
        responder \
        smbclient \
        ldap-utils \
        swaks \
        yara

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        graphviz \
        exploitdb \
        metasploit-framework \
        mitmproxy \
        pandoc

RUN python3 -m pip install --break-system-packages \
        bloodhound \
        impacket \
        sslyze

RUN apt-get update && apt-get install -y curl unzip jq ca-certificates \
    && DNSX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | jq -r '.tag_name' | sed 's/^v//') \
    && HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | jq -r '.tag_name' | sed 's/^v//') \
    && NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | sed 's/^v//') \
    && curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_${DNSX_VERSION}_linux_amd64.zip" -o /tmp/dnsx.zip \
    && curl -fsSL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_${HTTPX_VERSION}_linux_amd64.zip" -o /tmp/httpx.zip \
    && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -oq /tmp/dnsx.zip -d /usr/local/bin \
    && unzip -oq /tmp/httpx.zip -d /usr/local/bin \
    && unzip -oq /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/dnsx /usr/local/bin/httpx /usr/local/bin/nuclei \
    && rm -f /tmp/dnsx.zip /tmp/httpx.zip /tmp/nuclei.zip

COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --break-system-packages -r /app/requirements.txt

COPY . /app

RUN mkdir -p /app/backend/data

EXPOSE 4080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:4080/api/health > /dev/null || exit 1

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "4080"]
