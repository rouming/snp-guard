#!/bin/bash

# SNP-Guard Deployment Script

set -e

echo "🐳 Building SNP-Guard Docker image..."
docker build -t snp-guard .

echo "📁 Creating data directory..."
mkdir -p data/tls data/auth data/db data/artifacts/attestations data/artifacts/tmp data/logs

# Generate self-signed certs if not present
if [ ! -f "data/tls/server.crt" ] || [ ! -f "data/tls/server.key" ]; then
  echo "🔐 Generating self-signed TLS certificate in ./data ..."
  openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout data/tls/server.key \
    -out data/tls/server.crt \
    -days 365 \
    -subj "/CN=localhost"
  cp data/tls/server.crt data/tls/ca.pem
fi

echo "🚀 Starting SNP-Guard container..."
docker run -d \
  --name snp-guard \
  -p 3000:3000 \
  -v "$(pwd)/data:/data" \
  -e DATA_DIR=/data \
  --restart unless-stopped \
  snp-guard

echo "✅ SNP-Guard is now running!"
echo "🌐 Web UI: https://localhost:3000"
echo "📊 REST API: https://localhost:3000/v1"
echo ""
echo "To view logs: docker logs -f snp-guard"
echo "To stop: docker stop snp-guard && docker rm snp-guard"