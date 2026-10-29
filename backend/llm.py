"""Provider-agnostic chat call with tool support. Two wire protocols, not four: OpenAI, Gemini and a local OpenAI-compatible server
(vLLM/Ollama/sglang/...) all speak the same Chat Completions shape, so one adapter (_call_openai_compatible) covers all three, selected only
by base_url/key/model -- see PROVIDERS below. Claude's Messages API has a genuinely different request/response shape (tools, content blocks),
so it gets its own adapter. Returns (text, tool_calls) where tool_calls is a list of {"id", "name", "arguments": dict}."""
import asyncio
import json
import os
import re

import httpx

_TIMEOUT = httpx.Timeout(600.0, connect=10.0)
# qwen38-27b-sglang, confirmed live, does NOT separate a thinking-enabled response into the OpenAI-style "reasoning_content"
# field -- the raw <think>...</think> block (and anything before a bare, unopened "</think>" when the opening tag itself
# got swallowed by the chat template) comes back INSIDE "content" itself. Stripped before this ever reaches the chat loop
# or a tool-call parser, since raw reasoning text in the visible chat pane is never what the operator asked for.
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
_ORPHAN_CLOSE_THINK_RE = re.compile(r"^.*?</think>\s*", re.DOTALL)


def _strip_thinking_block(text: str) -> str:
    stripped = _THINK_BLOCK_RE.sub("", text)
    if stripped == text and "</think>" in text:
        stripped = _ORPHAN_CLOSE_THINK_RE.sub("", text)
    return stripped

PROVIDERS = {
    "gemini": {
        # Gemini's OpenAI-compatible endpoint -- same request/response shape as OpenAI's own Chat Completions API.
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "key_env": "GOOGLE_API_KEY",
        "model_env": "GEMINI_MODEL",
        "default_model": "gemini-3.8-flash",
    },
    # "local" (self-hosted qwen) deliberately removed 2026-10-27 for Aegis (the Meta Global Hackathon fork of Aegis): this build runs
    # on Muse Spark only -- see backend/web.py's providers() for the dropdown restriction. Aegis's own repo keeps "local".
    "claude": {
        "base_url": "https://api.anthropic.com/v1",
        "key_env": "ANTHROPIC_API_KEY",
        "model_env": "ANTHROPIC_MODEL",
        "default_model": "claude-sonnet-5-5",
    },
    # "gpt" deliberately removed 2026-10-27 for Aegis, same reason as "local" above -- Aegis's own repo keeps "gpt".
    "muse": {
        # Meta's Muse Spark, added 2026-10-27 for the Meta Global Hackathon (dev.meta.ai/events/global-hackathon) -- owner is still
        # signing up for an account; no MUSE_API_KEY exists yet, so available_providers() below correctly leaves this out of the dropdown
        # until one is set. Two sample snippets so far, both unverified against official docs but mutually consistent on the domain and
        # model id: (1) a Responses-API-style POST to api.meta.ai/v1/responses with {"reasoning": {"effort": ...}}; (2) the plain OpenAI
        # SDK's client.chat.completions.create against the SAME base_url (api.meta.ai/v1) and SAME model id ("muse-spark-1.3"), but
        # confirmed by the owner NOT to accept an effort/reasoning parameter at all. This is the EXACT split gpt-6-luna already has in
        # this file (_call_gpt_responses's own docstring: plain /v1/chat/completions forces reasoning_effort="none" the moment `tools` is
        # present; only the Responses API accepts a real effort level) -- so _call_muse below deliberately stays on the Responses-API
        # shape, reusing the same input/tool/output item helpers already written for gpt (_input_responses_shape/_tools_responses_shape),
        # specifically to keep effort control. UNVERIFIED: re-test every part of this (endpoint path, exact item shapes, auth header,
        # model id spelling, whether effort control actually works) against the real API the moment a MUSE_API_KEY exists -- see
        # model_pricing.py for the same caveat on cost.
        "base_url": "https://api.meta.ai/v1",
        "key_env": "MUSE_API_KEY",
        "model_env": "MUSE_MODEL",
        "default_model": "muse-spark-1.3",
        "reasoning_effort": "high",
    },
}


def available_providers() -> list:
    """Providers this host can actually use right now -- a key is configured in the environment. ("local" doesn't exist in this build's
    PROVIDERS at all -- see its own comment there -- so the base_url_env special-case Aegis's version of this function has is gone."""
    return [name for name, cfg in PROVIDERS.items() if os.environ.get(cfg["key_env"])]


def scan_fix_providers() -> tuple:
    """(scan_provider, fix_provider) from AEGIS_SCAN_PROVIDER/AEGIS_FIX_PROVIDER, or ("", "") if either is unset -- this is an
    opt-in, personal .env choice (never a public default): when both are set, core.py routes a plain scan/pentest request to scan_provider
    and a fix/remediate request to fix_provider automatically, instead of using one provider for the whole session."""
    scan = os.environ.get("AEGIS_SCAN_PROVIDER", "").strip().lower()
    fix = os.environ.get("AEGIS_FIX_PROVIDER", "").strip().lower()
    return (scan, fix) if scan and fix else ("", "")


def _tools_openai_shape(tool_schemas: list) -> list:
    return [{"type": "function", "function": s} for s in tool_schemas]


def _messages_openai_shape(messages: list) -> list:
    """Translates the universal message format (see chat()'s docstring) into real OpenAI Chat Completions shape -- an assistant message with
    tool_calls needs {"id","type":"function","function":{"name","arguments": <JSON string>}} per call, and content must be null (not "") when
    tool_calls are present; a tool-result message needs role "tool" with a "tool_call_id"."""
    out = []
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            out.append({"role": "assistant", "content": m.get("content") or None,
                        "tool_calls": [{"id": tc["id"], "type": "function", "function": {"name": tc["name"], "arguments": json.dumps(tc["arguments"])}} for tc in m["tool_calls"]]})
        elif m["role"] == "tool":
            out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            out.append({"role": m["role"], "content": m["content"]})
    return out


async def _call_openai_compatible(provider: str, messages: list, tool_schemas: list) -> tuple:
    """Only "gemini" reaches this in Aegis's build ("local" doesn't exist in PROVIDERS here -- see its own comment)."""
    cfg = PROVIDERS[provider]
    base_url = cfg["base_url"]
    if not base_url:
        raise RuntimeError(f"{provider}: no base URL configured")
    key = os.environ.get(cfg["key_env"], "") if cfg["key_env"] else ""
    model = os.environ.get(cfg["model_env"]) or cfg["default_model"]
    if not model:
        raise RuntimeError(f"{provider}: no model configured (set {cfg['model_env']})")
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": model, "messages": _messages_openai_shape(messages), "tools": _tools_openai_shape(tool_schemas), "tool_choice": "auto"}
    body.update(cfg.get("extra_body") or {})
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{base_url}/chat/completions", json=body, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(f"{provider} answered HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    msg = data["choices"][0]["message"]
    text = msg.get("content") or ""
    calls = []
    for tc in msg.get("tool_calls") or []:
        try:
            args = json.loads(tc["function"]["arguments"] or "{}")
        except ValueError:
            args = {}
        calls.append({"id": tc["id"], "name": tc["function"]["name"], "arguments": args})
    usage = data.get("usage") or {}
    return text, calls, {"model": model, "input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0)}


def _tools_claude_shape(tool_schemas: list) -> list:
    out = []
    for s in tool_schemas:
        out.append({"name": s["name"], "description": s.get("description", ""), "input_schema": s.get("parameters", {"type": "object", "properties": {}})})
    return out


async def _call_claude(messages: list, tool_schemas: list) -> tuple:
    cfg = PROVIDERS["claude"]
    key = os.environ.get(cfg["key_env"], "")
    if not key:
        raise RuntimeError("claude: no ANTHROPIC_API_KEY configured")
    model = os.environ.get(cfg["model_env"]) or cfg["default_model"]
    # Claude separates the system prompt from the message list and uses its own tool-result content-block shape.
    system = ""
    claude_messages = []
    for m in messages:
        if m["role"] == "system":
            system = (system + "\n" + m["content"]).strip()
        elif m["role"] == "tool":
            claude_messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}]})
        elif m["role"] == "assistant" and m.get("tool_calls"):
            blocks = ([{"type": "text", "text": m["content"]}] if m.get("content") else []) + \
                     [{"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["arguments"]} for tc in m["tool_calls"]]
            claude_messages.append({"role": "assistant", "content": blocks})
        else:
            claude_messages.append({"role": m["role"], "content": m["content"]})
    body = {"model": model, "max_tokens": 4096, "system": system, "messages": claude_messages, "tools": _tools_claude_shape(tool_schemas)}
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{cfg['base_url']}/messages", json=body, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(f"claude answered HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    text, calls = "", []
    for block in data.get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
        elif block.get("type") == "tool_use":
            calls.append({"id": block["id"], "name": block["name"], "arguments": block.get("input") or {}})
    usage = data.get("usage") or {}
    return text, calls, {"model": model, "input_tokens": usage.get("input_tokens", 0), "output_tokens": usage.get("output_tokens", 0)}


def _tools_responses_shape(tool_schemas: list) -> list:
    return [{"type": "function", "name": s["name"], "description": s.get("description", ""), "parameters": s.get("parameters", {"type": "object", "properties": {}})} for s in tool_schemas]


def _input_responses_shape(messages: list) -> tuple:
    """Translates the universal message format into the Responses API's flat `input` item list: a system message becomes
    {"role":"system",...} (Responses keeps it in input, unlike Claude's separate `system` field); an assistant tool call becomes a
    {"type":"function_call", call_id, name, arguments} item; a tool-result message becomes {"type":"function_call_output", call_id, output}."""
    out = []
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            if m.get("content"):
                out.append({"role": "assistant", "content": m["content"]})
            for tc in m["tool_calls"]:
                out.append({"type": "function_call", "call_id": tc["id"], "name": tc["name"], "arguments": json.dumps(tc["arguments"])})
        elif m["role"] == "tool":
            out.append({"type": "function_call_output", "call_id": m["tool_call_id"], "output": m["content"]})
        else:
            out.append({"role": m["role"], "content": m["content"]})
    return out




async def _call_muse(messages: list, tool_schemas: list, model_override: str = "") -> tuple:
    """Meta's Muse Spark -- confirmed working 2026-10-27 against a real MUSE_API_KEY (genuine model catalog from /v1/models, genuine
    tool-calling responses). model_override lets a caller pick "muse-spark-1.3-contributor" (10x cheaper, usage CAN train Meta's model)
    vs. the default "muse-spark-1.3" (owner's Standard tier, usage never trains it) PER CALL -- core.run_turn sets this based on whether
    the turn is working on a public repo (redteam_clone_repo) or a private one (redteam_clone_private_repo)/the self target, since only
    public repo content is safe to let train a third party's model. Passed explicitly rather than via an env var so concurrent sessions
    (or a mid-turn switch from public to private) can never race or leak one session's choice into another's."""
    cfg = PROVIDERS["muse"]
    key = os.environ.get(cfg["key_env"], "")
    if not key:
        raise RuntimeError("muse: no MUSE_API_KEY configured")
    model = model_override or os.environ.get(cfg["model_env"]) or cfg["default_model"]
    body = {
        "model": model,
        "input": _input_responses_shape(messages),
        "tools": _tools_responses_shape(tool_schemas),
        "reasoning": {"effort": cfg.get("reasoning_effort", "high")},
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{cfg['base_url']}/responses", json=body, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(f"muse answered HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    text, calls = "", []
    for item in data.get("output", []):
        if item.get("type") == "message":
            for block in item.get("content", []):
                if block.get("type") in ("output_text", "text"):
                    text += block.get("text", "")
        elif item.get("type") == "function_call":
            try:
                args = json.loads(item.get("arguments") or "{}")
            except ValueError:
                args = {}
            calls.append({"id": item["call_id"], "name": item["name"], "arguments": args})
    usage = data.get("usage") or {}
    return text, calls, {"model": model, "input_tokens": usage.get("input_tokens", 0), "output_tokens": usage.get("output_tokens", 0)}


async def _chat_once(provider: str, messages: list, tool_schemas: list, model_override: str = "") -> tuple:
    """(text, tool_calls, usage) for one LLM round. messages is the OpenAI-shaped history (system/user/assistant/tool roles) regardless of
    provider -- _call_claude/_call_muse translate it internally. usage is {"model", "input_tokens", "output_tokens"} -- see
    model_pricing.compute_cost_usd for turning it into a dollar figure. model_override is only ever consumed by _call_muse today.
    "gpt"/"local" don't exist in this build (Aegis is Muse-only -- see PROVIDERS' own comments) -- Aegis's version of this function
    has both."""
    if provider == "claude":
        return await _call_claude(messages, tool_schemas)
    if provider == "muse":
        return await _call_muse(messages, tool_schemas, model_override)
    if provider == "gemini":
        return await _call_openai_compatible(provider, messages, tool_schemas)
    raise ValueError(f"unknown provider {provider!r}; choose one of {sorted(PROVIDERS)}")


_CONNECT_RETRY_WAITS = (2.0, 5.0)    # seconds before the 2nd and 3rd attempt


async def chat(provider: str, messages: list, tool_schemas: list, model_override: str = "") -> tuple:
    """_chat_once, retried when the connection to the model server could not be OPENED (connect timeout / refused / DNS). Nothing was sent in
    that case, so repeating it is safe and cannot double-run anything. A real 2026-10-26 run lost its final answer to one 10 s connect
    timeout on the relay after the scan and report were already done; a read timeout or an HTTP error is NOT retried. model_override --
    see _call_muse's docstring -- is only meaningful for provider="muse"; every other provider ignores it."""
    for attempt, wait in enumerate((*_CONNECT_RETRY_WAITS, None), start=1):
        try:
            return await _chat_once(provider, messages, tool_schemas, model_override)
        except (httpx.ConnectTimeout, httpx.ConnectError) as e:
            from . import turnlog
            turnlog.log("llm_connect_retry", provider=provider, attempt=attempt, error=type(e).__name__, will_retry=wait is not None)
            if wait is None:
                raise
            await asyncio.sleep(wait)
