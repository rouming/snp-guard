#!/bin/bash

# SNP-Guard Deployment Script

set -e

echo "Building SNP-Guard Docker image..."
docker build -t snp-guard .

echo "Starting SNP-Guard container..."
docker run -d \
  --name snp-guard \
  -p 3000:3000 \
  -v "$(pwd)/data:/data" \
  -e DATA_DIR=/data \
  --restart unless-stopped \
  snp-guard

echo "SNP-Guard is now running!"
echo "Web UI: https://localhost:3000"
echo "REST API: https://localhost:3000/v1"
echo ""
echo "To view logs: docker logs -f snp-guard"
echo "To stop: docker stop snp-guard && docker rm snp-guard"
