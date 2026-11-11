FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Dedicated Linux UIDs for SPIRE unix workload attestation
RUN useradd -u 1001 -m authuser && \
    useradd -u 1002 -m mcpuser && \
    useradd -u 1003 -m agentuser && \
    useradd -u 1004 -m rogueuser

COPY . /app

