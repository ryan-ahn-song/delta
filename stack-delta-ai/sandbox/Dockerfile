FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sandbox \
    && useradd --uid 10001 --gid 10001 --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox

COPY --chmod=0555 entrypoint.sh /opt/stack-delta/entrypoint.sh
COPY --chmod=0444 env-sensor.cjs /opt/stack-delta/env-sensor.cjs

ENTRYPOINT ["/opt/stack-delta/entrypoint.sh"]

