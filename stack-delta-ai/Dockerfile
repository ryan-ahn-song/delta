FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . \
    && mkdir -p /app/data \
    && useradd --uid 10002 --home-dir /nonexistent --shell /usr/sbin/nologin stackdelta \
    && chown -R stackdelta:stackdelta /app/data

USER stackdelta
EXPOSE 8765
ENTRYPOINT ["stack-delta"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765"]

