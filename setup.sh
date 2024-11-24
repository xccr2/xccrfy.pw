#!/bin/bash

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Create instance directory for database
mkdir -p instance

# Initialize the database
python run_dev.py
