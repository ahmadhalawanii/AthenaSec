#!/bin/bash

export OLLAMA_MODELS="$(pwd)/models"
export OLLAMA_HOST="127.0.0.1:11434"

exec ./bin/bin/ollama serve
