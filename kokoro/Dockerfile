# Kokoro-82M TTS server (OpenAI-style /v1/audio/speech), CPU-only Mac/x86 variant. The DGX's own
# voice_servers/kokoro/Dockerfile starts FROM vllm/vllm-omni (CUDA, ARM64) -- wrong base for a laptop with no
# GPU, so this one starts from plain python:3.12-slim and installs torch's CPU wheel. Confirmed live on an
# Apple Silicon Mac: ~0.2-0.3s to synthesize a short sentence, ~2s for a ~280-char paragraph (see
# CLAUDE.md/memory for the measured numbers) -- CPU is not a usability problem for a single-operator demo.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends espeak-ng && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir "kokoro>=0.9.4" "misaki[en]" soundfile fastapi "uvicorn[standard]"
COPY server.py /app/server.py
ENV KOKORO_DEVICE=cpu
ENTRYPOINT ["python", "/app/server.py"]
