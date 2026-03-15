#!/bin/bash
export PYTHONPATH=$PYTHONPATH:.
echo "Starting Bug Bounty Co-Pilot God-Mode..."


# Ensure data directory exists for local persistence
mkdir -p data

# Start the background hunter daemon in the background
echo "Engaging Active Hunting Engine (Background Worker)..."
python -m src.core.background_worker &

# Start the REST API server
echo "Starting API Server on port ${PORT:-8000}..."
# We use 'python -m uvicorn' to ensure the module path is correctly handled
python -m uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT:-8000}
