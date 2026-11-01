FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user
WORKDIR /app
COPY --chown=user . /app
RUN mkdir -p /app/data /app/logs && chown -R user /app
USER user
ENV BIND_HOST=0.0.0.0 PORT=7860 PAYMENTS_DB=/app/data/payments.db
EXPOSE 7860
CMD ["python3", "-u", "market_server.py"]
