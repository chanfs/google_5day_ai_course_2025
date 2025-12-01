#!/bin/bash
echo "usage: source this file"

echo "Creating Python virtual environment..."
python3 -m venv ai_env

echo "Activating environment..."
source ai_env/bin/activate

echo "Installing google-adk..."
pip install google-adk

echo "Setup complete! Activate with: source ai_env/bin/activate"
source ai_env/bin/activate



echo "Virtual environment is now active! You're in: $(which python)"

