#!/usr/bin/env bash
# Start vLLM Qwen3 with NGC image for OpenClaw shim upstream (port 8000).
# Run after NVIDIA driver is loaded (e.g. after reboot or: sudo nvidia-modprobe).

set -e
IMAGE="nvcr.io/nvidia/vllm:25.12.post1-py3"
NAME="vllm-qwen3"

# Stop existing container if present
docker rm -f "$NAME" 2>/dev/null || true

docker run -d --gpus all --ipc=host --name "$NAME" \
  -p 8000:8000 \
  -v "${HOME}/.cache/huggingface:/root/.cache/huggingface" \
  "$IMAGE" \
  python3 -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen3-8B \
  --trust-remote-code \
  --enable-auto-tool-choice \
  --tool-call-parser llama3_json

echo "vLLM Qwen3 starting on http://127.0.0.1:8000 (logs: docker logs -f $NAME)"
