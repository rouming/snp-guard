#!/bin/bash

# SNP-Guard Deployment Script

set -e

echo "🐳 Building SNP-Guard Docker image..."
docker build -t snp-guard .

echo "📁 Creating data directory..."
mkdir -p data

echo "🚀 Starting SNP-Guard container..."
docker run -d \
  --name snp-guard \
  -p 3000:3000 \
  -v "$(pwd)/data:/data" \
  --restart unless-stopped \
  snp-guard

echo "✅ SNP-Guard is now running!"
echo "🌐 Web UI: http://localhost:3000"
echo "📊 gRPC API: localhost:50051"
echo ""
echo "To view logs: docker logs -f snp-guard"
echo "To stop: docker stop snp-guard && docker rm snp-guard"