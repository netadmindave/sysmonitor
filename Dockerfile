FROM python:3.12-slim

LABEL org.opencontainers.image.title="SysMonitor" \
      org.opencontainers.image.description="Syslog collector, rules, status polling and AI digests for Home Assistant" \
      org.opencontainers.image.source="https://github.com/netadmindave/sysmonitor"

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini tzdata ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pyyaml requests croniter paho-mqtt

WORKDIR /app
COPY sysmonitor/ /app/sysmonitor/
COPY config.default.yaml /app/

ENV SYSMONITOR_CONFIG=/config/config.yaml \
    PYTHONUNBUFFERED=1
VOLUME ["/config", "/data"]
EXPOSE 5514/udp 5514/tcp 8514/tcp

ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "sysmonitor"]
