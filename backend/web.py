"""Aegis's web UI: a FastAPI app serving the static page (templates/static below) and one WebSocket per browser tab. Each tab gets its
own message history (new_session()) and its own provider choice (the model dropdown) -- nothing is shared between tabs, no accounts, matching
the single-operator design the CLI already has. The WebSocket protocol is deliberately tiny:

  client -> server: {"type": "user_message", "text": "...", "provider": "gpt"}      (the dropdown choice, captured once on the first
                     message; "" leaves every later turn free to auto-route by wording if the operator's .env sets both
                     AEGIS_SCAN_PROVIDER and AEGIS_FIX_PROVIDER -- see core.pick_provider)
  server -> client: {"type": "chat", "text": "..."}                                  one per assistant text chunk
                     {"type": "terminal", "line": "..."}                             one per tool call/result and per live-progress line (ZAP)
                     {"type": "document", "filename", "mime", "size", "data_base64", "created_at"}   create_word_document's real file
                     {"type": "error", "text": "..."}                                 a provider/tool error, session stays open
                     {"type": "cost", "total_usd": 0.0123}                            the running session total, sent right before "done"
                     {"type": "done"}                                                 the turn finished, the input box re-enables
"""
import asyncio
import hashlib
import json
import os
import re
import uuid
from pathlib import Path

import httpx
import websockets
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from . import turnlog
from .core import ProviderError, new_session, pick_provider, run_turn
from .llm import available_providers, scan_fix_providers
from .model_pricing import compute_asr_cost_usd, compute_gemini_tts_cost_usd
from .tools.redteam_tools import check_scanner_versions

# muse-voice-transcribe-1.0's real cost isn't an LLM-token call, so it can't go through compute_cost_usd/session_cost_usd
# the way core.run_turn's rounds do -- it's billed per second of audio, attributed to a push-to-talk utterance that
# happens on a SEPARATE WebSocket (/ws/asr) from the chat one. Keyed by the chat ws's own ctx["sid"] (sent to the browser
# as a "sid" message right after it connects, see ws_endpoint below) so /ws/asr's cost finds its way back into the SAME
# session's displayed total. Single-operator design (see this file's own header) -- a module-level dict, not a DB row.
_asr_cost_by_sid: dict = {}
# Same pattern for gemini-3.8-live TTS (also a separate REST call, /api/tts, not an LLM round inside run_turn).
_gemini_tts_cost_by_sid: dict = {}

app = FastAPI()
_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# CSP base is 'self'-only (no wildcard fallback) with connect-src pinned to the REQUEST's own host below -- a plain
# "ws: wss:" scheme wildcard was tried first and ZAP's own CSP-validation rule (10055) flagged it as a wildcard
# directive; pinning to Host: is correct for any deployment (same-origin WebSocket clients always use the page's own
# host) and was verified clean against a live ZAP active scan.
_CSP_BASE = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
             "media-src 'self' blob: data:; object-src 'none'; base-uri 'self'; form-action 'self'; "
             "frame-ancestors 'none'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Adds X-Content-Type-Options, X-Frame-Options and Content-Security-Policy to every response.
    Fixes ZAP rules 10020 (clickjacking), 10021 (MIME sniffing) and 10038/10055 (CSP missing/wildcard) -- found
    2026-10-28 pentesting a cloned copy of this same code via cyberJiina; this is the real fix, applied here."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    host = request.headers.get("host", "")
    csp = f"{_CSP_BASE}; connect-src 'self' ws://{host} wss://{host}" if host else f"{_CSP_BASE}; connect-src 'self'"
    response.headers["Content-Security-Policy"] = csp
    return response


def _content_hash(filename: str) -> str:
    """Short content-hash for cache-busting -- replaces the old mtime-based ?v= (ZAP rule 10096, Timestamp
    Disclosure - Unix: a Unix timestamp in the URL is itself an information leak) with a value that changes
    only when the file's actual bytes change, keeping the same stale-asset protection with no leaked timestamp."""
    return hashlib.sha256((_STATIC_DIR / filename).read_bytes()).hexdigest()[:12]


@app.get("/")
async def index():
    # Cache-busting query params on style.css/app.js/markdown.js, from each file's own content hash -- a browser
    # that cached last week's app.js under a bare "/static/app.js" URL would otherwise keep serving it forever
    # (StaticFiles sets no Cache-Control, so this is purely about the URL changing, not a header).
    css_v = _content_hash("style.css")
    js_v = _content_hash("app.js")
    md_v = _content_hash("markdown.js")
    html = (_STATIC_DIR / "index.html").read_text()
    html = html.replace('href="/static/style.css"', f'href="/static/style.css?v={css_v}"')
    html = html.replace('src="/static/app.js"', f'src="/static/app.js?v={js_v}"')
    html = html.replace('src="/static/markdown.js"', f'src="/static/markdown.js?v={md_v}"')
    return HTMLResponse(html)


@app.get("/api/providers")
async def providers():
    """The model dropdown's own data source. Aegis-specific (2026-10-27, forked from Aegis for the Meta Global Hackathon): this is a
    Muse-Spark-only build -- "local" and "gpt" are deliberately removed from the offered list entirely, since the whole point of this fork
    is to run on Meta's own model. Gemini/Claude stay usable via AEGIS_PROVIDER/the auto-route env vars even though they're not in
    this list. "muse" is only offered once a real MUSE_API_KEY is configured, same gated-by-key pattern as every other provider -- never a
    dead option. auto_route is set only when the operator's .env configures BOTH AEGIS_SCAN_PROVIDER and AEGIS_FIX_PROVIDER --
    the frontend then offers an "auto" choice (empty provider string) that lets core.pick_provider route each message by its own wording,
    whatever those two env vars name."""
    avail = set(available_providers())
    scan_provider, fix_provider = scan_fix_providers()
    return {"providers": [p for p in ("muse",) if p in avail],
            "auto_route": {"scan": scan_provider, "fix": fix_provider} if scan_provider else None}


# Markdown-syntax stripping ported from Jiina's own TTS cleaner (sentence_stream.py's clean_for_speech, Jiina repo,
# utils/common_setup/) -- same rules, same reason: reading the raw text aloud (asterisks, headers, link syntax) breaks
# otherwise. Jiina's version does not strip emoji (her model rarely emits them), but Aegis's does ("green arrow...",
# spoken checkmarks) -- added here, not there, since it's this build's own real symptom.
_EMOJI_RE = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # pictographs, symbols, supplemental symbols/pictographs, extended-A
    "\U00002600-\U000027BF"  # misc symbols + dingbats (includes checkmarks, arrows like ✅, ➡)
    "\U0001F1E6-\U0001F1FF"  # regional indicators (flags)
    "\U00002190-\U000021FF"  # arrows
    "\U0000FE0F"             # variation selector-16 (emoji presentation)
    "\U0000200D"             # zero-width joiner (emoji sequences)
    "]+"
)


def clean_for_speech(text: str) -> str:
    """Strips markdown SYNTAX (not content), emoji, and makes money speakable before handing text to TTS."""
    t = re.sub(r"```[\s\S]*?```", "", text)
    t = re.sub(r"(?m)^#{1,6}\s+", "", t)
    t = re.sub(r"(?m)^\s*>\s?", "", t)
    t = re.sub(r"(?m)^\s*[-*_]{3,}\s*$", "", t)
    t = re.sub(r"(?m)^\s*[-*+]\s+", "", t)
    t = re.sub(r"(?m)^\s*\d+\.\s+", "", t)
    t = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", r"\1", t)
    t = re.sub(r"(\*\*\*|___)(.*?)\1", r"\2", t)
    t = re.sub(r"(\*\*|__)(.*?)\1", r"\2", t)
    t = re.sub(r"(\*|_)(.*?)\1", r"\2", t)
    t = re.sub(r"`([^`]*)`", r"\1", t)
    t = _EMOJI_RE.sub("", t)
    return re.sub(r"[ \t]+", " ", t).strip()


GEMINI_TTS_MODEL_NAME = os.environ.get("GEMINI_TTS_MODEL_NAME", "gemini-3.8-flash-lite-tts")


@app.get("/api/muse_ping")
async def muse_ping():
    """A cheap, real call to confirm MUSE_API_KEY actually works (not just that it's set) -- GET {base_url}/models, the
    same endpoint already confirmed genuine in llm.py's/_call_muse's own docstring ("real model catalog from /v1/models").
    Lets the page warn about a configured-but-broken key (no balance, revoked, wrong tier) instead of only discovering
    that on the first real chat turn."""
    key = os.environ.get("MUSE_API_KEY", "")
    if not key:
        return {"ok": False, "configured": False, "error": "MUSE_API_KEY is not set"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get("https://api.meta.ai/v1/models", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            return {"ok": True, "configured": True}
        return {"ok": False, "configured": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:                                                       # noqa: BLE001
        return {"ok": False, "configured": True, "error": f"{type(e).__name__}: {e}"}


@app.get("/api/gemini_ping")
async def gemini_ping():
    """Same idea as /api/muse_ping, for GOOGLE_API_KEY -- a plain REST ListModels call (works with a bare API key, unlike
    the Live API itself which needs the google-genai SDK) confirms the key is valid before the Voice toggle commits to it."""
    key = os.environ.get("GOOGLE_API_KEY", "")
    if not key:
        return {"ok": False, "configured": False, "error": "GEMINI_API_KEY (GOOGLE_API_KEY) is not set"}
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
        if r.status_code == 200:
            return {"ok": True, "configured": True}
        return {"ok": False, "configured": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:                                                       # noqa: BLE001
        return {"ok": False, "configured": True, "error": f"{type(e).__name__}: {e}"}


@app.get("/api/kokoro_ping")
async def kokoro_ping():
    """Confirms the local Kokoro-82M container (aegis-kokoro-tts, started by install.sh) is up and its model has
    loaded -- so the UI's TTS-backend picker can warn before the operator switches to it mid-demo. Unlike
    muse_ping/gemini_ping this needs no API key: Kokoro is local and free, AEGIS_KOKORO_URL is the only
    prerequisite (set by install.sh; absent only if this build predates the Kokoro container)."""
    base = os.environ.get("AEGIS_KOKORO_URL", "")
    if not base:
        return {"ok": False, "configured": False, "error": "AEGIS_KOKORO_URL is not set -- rerun install.sh to add the aegis-kokoro-tts container"}
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"{base}/health")
        if r.status_code == 200:
            return {"ok": True, "configured": True}
        return {"ok": False, "configured": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:                                                       # noqa: BLE001
        return {"ok": False, "configured": True, "error": f"{type(e).__name__}: {e}"}


@app.post("/api/tts_kokoro")
async def tts_kokoro(request: Request):
    """Voice toggle's local-TTS path: proxies text to the aegis-kokoro-tts container's OpenAI-shaped
    /v1/audio/speech (see kokoro/server.py) and relays the WAV bytes back as-is. Added 2026-10-29 as an
    open-source alternative to the browser's Web Speech API and to Gemini TTS -- no API key, no per-call cost,
    runs entirely on this machine (CPU is fine for a single-operator demo; see kokoro/Dockerfile's own note on
    measured latency). Body: {"text": "...", "sid": "..."} -- sid is accepted for symmetry with /api/tts but
    costs nothing, so no _*_cost_by_sid entry is ever written for it."""
    body = await request.json()
    text = clean_for_speech(str(body.get("text") or ""))
    if not text:
        return Response(status_code=400, content=b"no text")
    base = os.environ.get("AEGIS_KOKORO_URL", "")
    if not base:
        return Response(status_code=503, content=b"Local TTS is not configured: AEGIS_KOKORO_URL is not set (rerun install.sh)")
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(f"{base}/v1/audio/speech", json={"input": text, "response_format": "wav"})
    except Exception as e:                                                       # noqa: BLE001 -- the container may still be downloading the model on first boot
        print(f"[tts/kokoro] raised {type(e).__name__}: {e}", flush=True)
        return Response(status_code=502, content=f"{type(e).__name__}: {e}".encode())
    if r.status_code != 200:
        return Response(status_code=502, content=r.content[:600] or b"Kokoro TTS returned an error")
    return Response(status_code=200, content=r.content, media_type="audio/wav")


@app.post("/api/tts")
async def tts(request: Request):
    """Voice toggle ON's spoken reply: a one-shot gemini-3.8-flash-lite-tts call (text in, audio out). Switched
    2026-10-28 from gemini-3.8-live (the full-duplex Live API, meant for audio-in/audio-out relays -- Aegis only
    ever sends text, never audio-in, so the dedicated one-shot TTS model is both the right fit and meaningfully
    cheaper: $0.50/1M text input + $6.00/1M audio output, vs Live's $3.00/1M + $12.00/1M audio rates). Pattern and
    the one hard gotcha both verified against Jiina's own route_speech.py._gemini_synthesize_sync: this model
    rejects system_instruction outright and has no instruction-following separation at all -- it is a literal
    speak-whatever-is-in-contents engine, so `contents` must be ONLY the raw text, never a wrapper/instruction.
    See /api/tts_kokoro for the local, free, open-source alternative (added 2026-10-29) and the browser's own
    Web Speech API (app.js) for the zero-backend default. Body: {"text": "...", "sid": "<chat ws's ctx[\"sid\"]>"}. This
    model's response `inline_data.data` is already a complete WAV file (unlike the Live API's raw PCM16, which
    needed manual header-wrapping) -- returned to the browser as-is."""
    body = await request.json()
    text = clean_for_speech(str(body.get("text") or ""))
    sid = str(body.get("sid") or "")
    if not text:
        return Response(status_code=400, content=b"no text")
    key = os.environ.get("GOOGLE_API_KEY", "")
    if not key:
        return Response(status_code=503, content=b"Voice is not configured: GOOGLE_API_KEY is not set")
    try:
        from google import genai
        from google.genai import types
        client = genai.Client(api_key=key)
        resp = await client.aio.models.generate_content(
            model=GEMINI_TTS_MODEL_NAME,
            contents=text,
            config=types.GenerateContentConfig(
                response_modalities=["AUDIO"],
                speech_config=types.SpeechConfig(
                    voice_config=types.VoiceConfig(
                        prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name="Kore")
                    )
                ),
            ),
        )
    except Exception as e:                                                       # noqa: BLE001 -- a bad/expired key or quota error must become a visible banner, never a 500 traceback
        print(f"[tts/gemini] raised {type(e).__name__}: {e}", flush=True)
        return Response(status_code=502, content=f"{type(e).__name__}: {e}".encode())

    wav = None
    for cand in resp.candidates or []:
        for part in cand.content.parts:
            if part.inline_data and part.inline_data.data:
                wav = part.inline_data.data
                break
        if wav:
            break
    if wav is None:
        return Response(status_code=502, content=b"Gemini TTS returned no audio data")

    if sid:
        cost = compute_gemini_tts_cost_usd(resp.usage_metadata)
        _gemini_tts_cost_by_sid[sid] = _gemini_tts_cost_by_sid.get(sid, 0.0) + cost

    return Response(status_code=200, content=wav, media_type="audio/wav")


@app.websocket("/ws/asr")
async def ws_asr(ws: WebSocket):
    """Push-to-talk's microphone side: the browser streams raw mic audio here over a plain WebSocket, this relays it straight
    through to Meta's own realtime ASR (muse-voice-transcribe-1.0, wss://api.meta.ai/v1/asr/realtime), and relays Meta's
    transcript events back -- so MUSE_API_KEY stays server-side, never shipped to the browser.

    Schema confirmed 2026-10-27 against Meta's own official client code (github.com/meta-models/meta-model-cookbook,
    06_muse_voice/01_voice_api_fundamentals/utils.py) -- the earlier version of this function was built on an unofficial
    SDK guess that never got past the handshake; this one follows the real client exactly:
      - the credential rides INSIDE the handshake JSON (`authorization.accessToken`), not an HTTP header -- the header
        form is only for the one-shot /v1/asr/transcribe endpoint, never the realtime one.
      - mode is PUSH_TO_TALK (we decide the turn boundary, by sending endStream on mic release -- matches this UI).
      - the handshake ack is a BARE `{"sessionId": "..."}` with no "type" field; a rejected handshake comes back
        as `{"type":"error","message":"..."}` and must be read before any audio is sent.
      - partials are CUMULATIVE (each one replaces the last, matching the input box's live-update behaviour already
        written client-side) and arrive as `{"type":"transcript","transcript":"...","final":bool}`.
    Browser protocol:
      client -> server: binary frames of raw PCM16 24kHz mono mic audio, until it stops talking (push-to-talk release)
                         an empty binary frame signals end-of-utterance (mic released)
      server -> client: {"type": "partial", "text": "..."}   interim transcript, replaces the previous partial
                         {"type": "final", "text": "..."}     final transcript for this utterance
                         {"type": "error", "text": "..."}
    """
    await ws.accept()
    sid = ws.query_params.get("sid", "")   # the chat ws's own ctx["sid"] -- see its "sid" message right after connect
    bytes_sent = 0                          # PCM16 mono @ 24kHz -- real audio actually relayed, independent of anything Meta reports back
    api_key = os.environ.get("MUSE_API_KEY", "")
    if not api_key:
        await ws.send_text(json.dumps({"type": "error", "text": "push-to-talk is not configured: MUSE_API_KEY is not set"}))
        await ws.close()
        return
    asr_url = os.environ.get("MUSE_ASR_WS_URL", "wss://api.meta.ai/v1/asr/realtime")
    try:
        async with websockets.connect(asr_url, open_timeout=10, max_size=None) as upstream:
            await upstream.send(json.dumps({
                "mode": "PUSH_TO_TALK",
                "authorization": {"accessToken": api_key},
                "audioEncoding": "PCM_24KHZ",
                "model": "muse-voice-transcribe-1.0",
                "partialMode": "CUMULATIVE",
                "emitAudioProgress": False,
            }))
            # The server always answers the handshake first (sessionId, or an error) before any transcript event --
            # read it before sending audio so a rejected handshake surfaces cleanly instead of as a closed socket
            # mid-upload.
            ack_raw = await upstream.recv()
            try:
                ack = json.loads(ack_raw)
            except ValueError:
                ack = {}
            if ack.get("type") == "error":
                await ws.send_text(json.dumps({"type": "error", "text": ack.get("message", "handshake rejected")}))
                await ws.close()
                return

            async def pump_browser_to_meta():
                nonlocal bytes_sent
                while True:
                    msg = await ws.receive()
                    if msg.get("type") == "websocket.disconnect":
                        break
                    if msg.get("bytes") is not None:
                        data = msg["bytes"]
                        if not data:   # empty binary frame = mic released -- half-close the audio input
                            await upstream.send(json.dumps({"type": "endStream"}))
                        else:
                            bytes_sent += len(data)
                            await upstream.send(data)

            async def pump_meta_to_browser():
                async for raw in upstream:
                    if isinstance(raw, bytes):
                        continue
                    try:
                        evt = json.loads(raw)
                    except ValueError:
                        continue
                    kind = evt.get("type", "")
                    if kind == "transcript":
                        await ws.send_text(json.dumps({"type": "final" if evt.get("final") else "partial", "text": evt.get("transcript", "")}))
                    elif kind == "speechComplete":
                        await ws.send_text(json.dumps({"type": "final", "text": evt.get("transcript", "").strip()}))
                    elif kind == "error":
                        await ws.send_text(json.dumps({"type": "error", "text": evt.get("message", str(evt))}))

            browser_task = asyncio.ensure_future(pump_browser_to_meta())
            meta_task = asyncio.ensure_future(pump_meta_to_browser())
            done, pending = await asyncio.wait({browser_task, meta_task}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except WebSocketDisconnect:
        pass
    except Exception as e:                                                       # noqa: BLE001 -- a bad upstream must never crash the server
        print(f"[ws/asr] raised {type(e).__name__}: {e}", flush=True)
        try:
            await ws.send_text(json.dumps({"type": "error", "text": f"{type(e).__name__}: {e}"}))
        except Exception:
            pass
    finally:
        if bytes_sent and sid:
            seconds = bytes_sent / (24000 * 2)   # PCM16 mono @ 24kHz -> 2 bytes/sample
            delta = compute_asr_cost_usd(seconds)
            _asr_cost_by_sid[sid] = _asr_cost_by_sid.get(sid, 0.0) + delta
            # The chat ws (a SEPARATE connection) only re-sends the full "cost" total at the end of its next turn --
            # this lets the displayed total update immediately after an utterance, rather than looking stale until
            # the operator sends another message. app.js adds this delta to whatever it's currently showing.
            try:
                await ws.send_text(json.dumps({"type": "cost_delta", "usd": delta}))
            except Exception:
                pass
        try:
            await ws.close()
        except Exception:
            pass


def _maybe_announce_muse_billing(messages: list, ctx: dict, provider: str) -> None:
    """Once per session, the moment "muse" is first the active provider, tells the model to disclose the public/contributor vs.
    private/Standard billing split in its own next reply -- added 2026-10-27, owner's own instruction: the operator should be told this
    up front, not just have it happen silently in the background. core.run_turn's repo_visibility tracking (see its own comment) is what
    actually picks the model per call; this only makes the model SAY what it's doing."""
    if provider != "muse" or ctx.get("muse_billing_announced"):
        return
    ctx["muse_billing_announced"] = True
    messages.append({"role": "system", "content": (
        "You are now running on Meta's Muse Spark. Your VERY NEXT REPLY's TEXT must be the FULL disclosure below, written out in "
        "full -- never a short label or summary of it, never anything shorter than a real explanation. Use this almost verbatim, "
        "in your own voice: \"Hi, I am Aegis. Quick note: I work on public repos using the cheaper Muse contributor model, so "
        "public repo code may be used for training. Private repos or my own code use the regular Muse model and are never used for "
        "training.\" Say this ONCE, this exact level of detail, not a terser version. You still call check_scanner_versions in this "
        "SAME round as normal (the tool call is unaffected by this instruction, only the TEXT is) -- do NOT mention scanner "
        "versions or anything else in this reply's text; that starts in the round after, once the tool result is back, with "
        "something like \"Checking my scanner versions now.\""
    )})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    messages = new_session()
    dropdown_choice = ""   # taken from each message's "provider" field; "" lets pick_provider auto-route every turn

    async def on_text(text: str) -> None:
        await ws.send_text(json.dumps({"type": "chat", "text": text}))

    async def on_tool_call(name: str, args: dict, result: str) -> None:
        # The whole command, not a 200-char cut: the owner wants to see every command she runs. Only a very long value (a report body,
        # a pasted file) is replaced by its size so one line cannot flood the pane.
        shown = {k: (f"<{len(v)} chars>" if isinstance(v, str) and len(v) > 1500 else v) for k, v in (args or {}).items()}
        preview = json.dumps(shown, ensure_ascii=False)
        await ws.send_text(json.dumps({"type": "terminal", "line": f"-> {name}({preview})"}))
        await ws.send_text(json.dumps({"type": "terminal", "line": f"   {result[:600]}"}))

    async def emit_terminal_progress(name: str, text: str) -> None:
        """pentest_zap's live spider/active-scan progress -- see redteam_tools.py's ctx["emit_terminal_progress"] call site."""
        await ws.send_text(json.dumps({"type": "terminal", "line": f"[{name}] {text}"}))

    async def emit_document(doc: dict) -> None:
        """create_word_document's real file -- sent as its OWN message type, never folded into a "terminal" line (those truncate to
        600 chars; a docx's base64 would both blow past that and clutter the terminal pane with binary noise)."""
        await ws.send_text(json.dumps({"type": "document", **doc}))
        await ws.send_text(json.dumps({"type": "terminal", "line": f"[report] {doc['filename']} ({round(doc['size'] / 1024)} KB) -- see the download card"}))

    async def emit_status(text: str) -> None:
        """A short transient 'now doing X' line for the chat pane (empty text clears it). Never stored as a chat message."""
        await ws.send_text(json.dumps({"type": "status", "text": text}))

    ctx = {"emit_status": emit_status, "emit_terminal_progress": emit_terminal_progress, "emit_document": emit_document, "sid": uuid.uuid4().hex[:6]}
    # Lets core.py's per-task cost line include ASR/TTS spend (tracked here, module-level, keyed by sid) without
    # core.py importing web.py (circular) -- see core.py's _task_cost().
    ctx["_asr_tts_cost_fn"] = lambda: _asr_cost_by_sid.get(ctx["sid"], 0.0) + _gemini_tts_cost_by_sid.get(ctx["sid"], 0.0)
    turnlog.log("session_open", sid=ctx["sid"])
    # Lets the browser attribute push-to-talk's /ws/asr cost (billed per utterance, on a separate WebSocket -- see
    # _asr_cost_by_sid above) back to THIS session's displayed total, by passing it as /ws/asr?sid=...
    await ws.send_text(json.dumps({"type": "sid", "sid": ctx["sid"]}))

    def _total_cost_usd() -> float:
        return (ctx.get("session_cost_usd", 0.0) + _asr_cost_by_sid.get(ctx["sid"], 0.0)
                + _gemini_tts_cost_by_sid.get(ctx["sid"], 0.0))

    # Specifically "muse" missing -- not "no provider at all" (available_providers() now also sees GOOGLE_API_KEY,
    # added 2026-10-27 for the Voice toggle's TTS; that key has nothing to do with chat on this Muse-only build, and
    # must never make this fallback think a chat provider exists when it doesn't -- see core.pick_provider's own
    # fix for the matching bug on the actual provider-selection path). run_turn can't do anything useful without
    # "muse" specifically (the dropdown's only real option), so skip straight to a deterministic, non-LLM fallback:
    # a fixed greeting sentence plus a REAL scanner-version check (check_scanner_versions needs no model, just the
    # redteam container), then stop. Send stays disabled -- the frontend gates that off /api/providers too.
    if "muse" not in available_providers():
        await ws.send_text(json.dumps({"type": "chat", "text": (
            "Hi, I'm Aegis. **MUSE_API_KEY is not set** on this host, so I can't chat yet -- copy `.env.example` to "
            "`.env` and fill it in, then reload this page. In the meantime, here's my scanner tooling status:"
        )}))
        try:
            result = await check_scanner_versions({}, ctx)
            await ws.send_text(json.dumps({"type": "terminal", "line": "-> check_scanner_versions()"}))
            await ws.send_text(json.dumps({"type": "terminal", "line": f"   {result[:600]}"}))
            # Real shape, redteam/server.py's /scanner_versions: {"ok": bool, "tools": [{"name","current","latest","status",...}]}.
            parsed = json.loads(result)
            lines = []
            for tool in parsed.get("tools", []) if isinstance(parsed, dict) else []:
                name, current, latest, status = tool.get("name", "?"), tool.get("current", "?"), tool.get("latest"), tool.get("status")
                if status == "latest" or status == "system-managed":
                    lines.append(f"- ✅ {name} {current} (latest)" if status == "latest" else f"- ✅ {name} {current} (system-managed)")
                elif status == "update_available":
                    lines.append(f"- ⚠️ {name} {current} → {latest} available")
                else:
                    lines.append(f"- ❓ {name}: version check failed ({tool.get('error', 'unknown error')})")
            if lines:
                await ws.send_text(json.dumps({"type": "chat", "text": "\n".join(lines)}))
        except Exception as e:                                                  # noqa: BLE001 -- the fallback path itself must never crash the socket
            await ws.send_text(json.dumps({"type": "error", "text": f"Scanner version check failed: {type(e).__name__}: {e}"}))
        await ws.send_text(json.dumps({"type": "done"}))
    else:
        await _run_greeting(ws, messages, ctx, on_text, on_tool_call, _total_cost_usd)

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if msg.get("type") != "user_message":
                continue
            if "muse" not in available_providers():
                await ws.send_text(json.dumps({"type": "error", "text": "No LLM provider is configured (MUSE_API_KEY is not set)."}))
                await ws.send_text(json.dumps({"type": "done"}))
                continue
            text = str(msg.get("text") or "").strip()
            if not text:
                continue
            if "provider" in msg:                      # the dropdown can change between tasks: honour the latest choice
                dropdown_choice = str(msg.get("provider", "")).strip()
            try:
                # Re-picked every turn, not cached: if the operator left the dropdown on "auto" (dropdown_choice=="")
                # and has a personal AEGIS_SCAN_PROVIDER/AEGIS_FIX_PROVIDER split configured, each message's
                # OWN wording decides scan vs fix routing -- see core.pick_provider.
                provider = pick_provider(dropdown_choice, user_text=text)
            except ProviderError as e:
                await ws.send_text(json.dumps({"type": "error", "text": str(e)}))
                await ws.send_text(json.dumps({"type": "done"}))
                continue
            await ws.send_text(json.dumps({"type": "terminal", "line": f"provider: {provider}"}))
            _maybe_announce_muse_billing(messages, ctx, provider)
            messages.append({"role": "user", "content": text})
            try:
                await run_turn(provider, messages, ctx, on_text, on_tool_call)
            except Exception as e:                                               # noqa: BLE001 -- a bad LLM response must never kill the socket
                # Printed to stdout (docker logs) too -- previously this error only ever reached the client's chat pane,
                # so a real exception left ZERO trace in the server's own logs, making "did it actually error, or did the
                # client just lose the message" impossible to tell from the server side alone.
                print(f"[ws] run_turn raised {type(e).__name__}: {e}", flush=True)
                await ws.send_text(json.dumps({"type": "error", "text": f"{type(e).__name__}: {e}" if str(e) else
                                               f"{type(e).__name__}: could not reach the model server (tried 3 times). Your scan and any report already made are not lost -- send your message again."}))
            # The FINAL value for this turn -- run_turn has already finished accumulating every LLM round's cost into
            # ctx["session_cost_usd"] by the time we get here, so this is always the up-to-date running total, never a
            # partial mid-turn figure.
            await ws.send_text(json.dumps({"type": "cost", "total_usd": _total_cost_usd()}))
            await ws.send_text(json.dumps({"type": "done"}))
    except WebSocketDisconnect:
        print("[ws] client disconnected", flush=True)
        turnlog.log("session_close", sid=ctx["sid"], turns=ctx.get("turn_no", 0), session_cost_usd=round(ctx.get("session_cost_usd", 0.0), 4))
    except Exception as e:                                                        # noqa: BLE001 -- log anything else that would otherwise vanish silently
        print(f"[ws] ws_endpoint raised {type(e).__name__}: {e}", flush=True)


async def _run_greeting(ws, messages, ctx, on_text, on_tool_call, _total_cost_usd) -> None:
    try:
        provider = pick_provider("", user_text="hello")  # Use default provider for greeting
        await ws.send_text(json.dumps({"type": "terminal", "line": f"provider: {provider}"}))
        _maybe_announce_muse_billing(messages, ctx, provider)
        messages.append({"role": "user", "content": "Hi"})  # Minimal trigger to start the greeting
        ctx["greeting"] = True      # the greeting is not a user task: no "Completed task in" line
        try:
            await run_turn(provider, messages, ctx, on_text, on_tool_call)
        finally:
            ctx["greeting"] = False
        await ws.send_text(json.dumps({"type": "cost", "total_usd": _total_cost_usd()}))
        await ws.send_text(json.dumps({"type": "done"}))
    except Exception as e:
        print(f"[ws] greeting raised {type(e).__name__}: {e}", flush=True)
        await ws.send_text(json.dumps({"type": "error", "text": f"Greeting failed: {e}"}))
        await ws.send_text(json.dumps({"type": "done"}))
