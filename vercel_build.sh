#!/usr/bin/env bash

# Exit on any error
set -e

# Ensure we're in the correct directory
cd ${VERCEL_WORK_PATH:-$(pwd)}

# Use Python from the environment
PYTHON_CMD=${PYTHON:-python3}
PIP_CMD=${PIP:-pip3}

# Check if Python is available
if ! command -v $PYTHON_CMD &> /dev/null
then
    echo "Python could not be found"
    exit 1
fi

# Check if pip is available
if ! command -v $PIP_CMD &> /dev/null
then
    echo "pip could not be found"
    exit 1
fi

# Upgrade pip
$PYTHON_CMD -m $PIP_CMD install --upgrade pip

# Install requirements
$PIP_CMD install -r requirements.txt

echo "Build completed successfully!"