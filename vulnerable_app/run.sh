#!/bin/bash
echo "Building Docker image..."
docker build -t vulnerable-app .

echo "Stopping and removing existing container (if any)..."
docker stop vulnerable-app-c &> /dev/null
docker rm vulnerable-app-c &> /dev/null

echo "Running vulnerable app container on port 5000..."
docker run -d -p 5000:5000 --name vulnerable-app-c vulnerable-app
echo "Vulnerable app should be running at http://localhost:5000"
echo "To stop: docker stop vulnerable-app-c"
echo "To view logs: docker logs -f vulnerable-app-c"
