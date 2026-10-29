"""Kokoro-82M as a small HTTP service, shaped like OpenAI's speech endpoint so callers need no special client.

  POST /v1/audio/speech  {"input": "...", "voice": "af_heart", "speed": 1.0, "response_format": "wav"|"pcm"}
  GET  /v1/models        GET /health

wav = 24 kHz mono 16-bit (the format Kokoro produces); pcm = the same samples without a header.
Device: KOKORO_DEVICE=cuda|cpu (default cuda when available). ~1 GB GPU, or none on cpu."""
import io, os, threading, time
import numpy as np, soundfile as sf, torch, uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from kokoro import KPipeline
from pydantic import BaseModel

SAMPLE_RATE = 24000
MODEL_NAME = os.getenv("KOKORO_MODEL_NAME", "kokoro-82m")
DEFAULT_VOICE = os.getenv("KOKORO_DEFAULT_VOICE", "af_heart")
DEVICE = os.getenv("KOKORO_DEVICE") or ("cuda" if torch.cuda.is_available() else "cpu")
MAX_CHARS = int(os.getenv("KOKORO_MAX_CHARS", "5000"))

_pipelines: dict = {}
_lock = threading.Lock()  # one synthesis at a time; the model is tiny and this keeps GPU memory flat


def _pipeline(lang_code: str) -> KPipeline:
    if lang_code not in _pipelines:
        _pipelines[lang_code] = KPipeline(lang_code=lang_code, repo_id="hexgrad/Kokoro-82M", device=DEVICE)
    return _pipelines[lang_code]


class SpeechRequest(BaseModel):
    input: str
    model: str | None = None
    voice: str | None = None
    speed: float = 1.0
    response_format: str = "wav"


app = FastAPI(title="kokoro-tts")


@app.get("/health")
def health():
    return {"status": "ok", "device": DEVICE, "model": MODEL_NAME}


@app.get("/v1/models")
def models():
    return {"object": "list", "data": [{"id": MODEL_NAME, "object": "model", "owned_by": "hexgrad"}]}


@app.post("/v1/audio/speech")
def speech(req: SpeechRequest):
    text = (req.input or "").strip()
    if not text:
        raise HTTPException(400, "input is empty")
    if len(text) > MAX_CHARS:
        raise HTTPException(413, f"input is {len(text)} characters; the limit is {MAX_CHARS}")
    if req.response_format not in ("wav", "pcm"):
        raise HTTPException(400, "response_format must be 'wav' or 'pcm'")
    voice = req.voice or DEFAULT_VOICE
    lang = voice[0]  # Kokoro voice ids start with the language code (a=American, b=British, ...)
    started = time.time()
    try:
        with _lock:
            chunks = [np.asarray(a, dtype=np.float32) for _, _, a in _pipeline(lang)(text, voice=voice, speed=req.speed) if a is not None]
    except Exception as exc:
        raise HTTPException(400, f"synthesis failed for voice '{voice}': {exc}")
    if not chunks:
        raise HTTPException(422, "no audio was produced for that input")
    audio = np.concatenate(chunks)
    pcm16 = (np.clip(audio, -1.0, 1.0) * 32767).astype(np.int16)
    headers = {"X-Audio-Seconds": f"{len(pcm16) / SAMPLE_RATE:.2f}", "X-Synthesis-Seconds": f"{time.time() - started:.2f}"}
    if req.response_format == "pcm":
        return Response(pcm16.tobytes(), media_type="audio/L16;rate=24000", headers=headers)
    buf = io.BytesIO()
    sf.write(buf, pcm16, SAMPLE_RATE, format="WAV", subtype="PCM_16")
    return Response(buf.getvalue(), media_type="audio/wav", headers=headers)


if __name__ == "__main__":
    _pipeline("a")  # load now so the first request is fast and a bad install fails at startup
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("KOKORO_PORT", "8095")))
