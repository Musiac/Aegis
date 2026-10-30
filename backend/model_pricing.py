"""Per-model $/1M-token rates, used to turn each LLM call's real token usage into a running session cost. Aegis fork of Aegis's own
model_pricing.json (2026-10-27, Meta Global Hackathon) -- gpt-5.1/gpt-6-luna removed since this build has no "gpt"/"local" provider at all
(see llm.PROVIDERS' own comments); Muse Spark is the one this fork actually runs on."""

_RATES_PER_1M_USD = {
    "gemini-3.8-flash": (0.75, 3.75),  # https://ai.google.dev/gemini-api/docs/pricing -- verified 2026-10-26 (see the full-featured version's model_pricing.json)
    "claude-sonnet-5-5": (2.0, 10.0),  # https://platform.claude.com/docs/en/about-claude/pricing -- verified 2026-10-26 (see the full-featured version's model_pricing.json)
    # https://dev.meta.ai/docs/pricing-rate-limits -- verified 2026-10-27 against a real, live MUSE_API_KEY (confirmed genuine: real
    # model catalog from /v1/models, real tool-calling response from /v1/responses). Standard (non-contributor) tier -- the default, used
    # whenever a target isn't confirmed public (see core.run_turn's repo_visibility tracking); contributor is the public-repo tier.
    "muse-spark-1.3": (1.25, 4.25),
    "muse-spark-1.3-contributor": (0.10, 0.20),
    # https://dev.meta.ai/docs/pricing-rate-limits -- verified 2026-10-30 directly on the page (fetched live, not memory): Standard mode
    # $4.00/1M input, $20.00/1M output. Flat rate regardless of reasoning.effort (none/minimal/low/medium/high/xhigh/max all bill the
    # same). Contributor mode is explicitly "Not available" for Wonder on the page -- unlike Spark, there is no cheaper tier at all, so
    # this is the only (non-cached) rate muse-wonder-1.0 will ever use.
    "muse-wonder-1.0": (4.00, 20.00),
}

# Cached-input rate per 1M tokens, where it differs from the plain input rate above -- a model absent here is assumed to have no
# separate cached rate (compute_cost_usd then prices 100% of its input tokens at the full rate, same as before this existed).
# All three reasoning models verified 2026-10-30 directly on https://dev.meta.ai/docs/pricing-rate-limits (fetched live, not memory):
#   muse-wonder-1.0:              $0.20  cached vs $4.00 input, $20.00 output
#   muse-spark-1.3 (Standard):    $0.15  cached vs $1.25 input, $4.25  output
#   muse-spark-1.3-contributor:   $0.002 cached vs $0.10 input, $0.20  output
# A real incident caught this 2026-10-30: an estimate using the flat (non-cached) input rate on ALL input tokens of a real 80-round
# muse-wonder-1.0 run overstated its cost by ~5x against Meta's own billing dashboard (91.1% cache hit rate on that run, confirmed
# live by the owner) -- every multi-round tool-calling session resends the whole growing conversation history each round, so the
# cache hit rate over a long session is naturally very high. muse-voice-transcribe-1.0 (compute_asr_cost_usd, below) has NO cached-
# input concept at all on the same pricing page -- it bills per second of audio, a completely separate line item from token usage,
# so it is deliberately absent from this table rather than given a meaningless 0.
_CACHED_INPUT_RATE_PER_1M_USD = {
    "muse-wonder-1.0": 0.20,
    "muse-spark-1.3": 0.15,
    "muse-spark-1.3-contributor": 0.002,
}

# https://dev.meta.ai/docs/pricing-rate-limits -- verified 2026-10-27 directly on the page (confirmed by WebFetch, not
# memory): $0.18 per hour of audio processed, metered per whole second, same rate for streaming (what Aegis's push-to-talk
# uses, see web.py's /ws/asr) and non-streaming/batch transcription.
MUSE_VOICE_TRANSCRIBE_USD_PER_SECOND = 0.18 / 3600.0

# gemini-3.8-flash-lite-tts's real rates, ported from Jiina's own verified model_pricing.json entry (Jiina repo,
# utils/common_setup/model_pricing.json) -- https://ai.google.dev/gemini-api/docs/pricing, verified there 2026-10-26.
# Switched 2026-10-28 from gemini-3.8-live ($3.00/1M audio input, $12.00/1M audio output -- the full-duplex Live API,
# audio rates) to this dedicated one-shot TTS model, which is meaningfully cheaper for Aegis's actual use (text in,
# audio out, never audio in): $0.50/1M TEXT input, $6.00/1M AUDIO output -- half the output rate alone.
GEMINI_TTS_USD_PER_1M_TEXT_INPUT = 0.5
GEMINI_TTS_USD_PER_1M_AUDIO_OUTPUT = 6.0


def compute_gemini_tts_cost_usd(usage_metadata) -> float:
    """Real cost of one gemini-3.8-flash-lite-tts call. Unlike the Live API's usage_metadata (which breaks prompt/
    response tokens out per modality), this model's generate_content usage_metadata is flat --
    prompt_token_count (the input text) and candidates_token_count (the output audio) -- matching Jiina's own
    route_speech.py._gemini_synthesize_sync, which reads the same two fields. Unrounded (like compute_cost_usd
    above) -- only the final DISPLAYED total is rounded, client-side."""
    if usage_metadata is None:
        return 0.0
    prompt_tokens = getattr(usage_metadata, "prompt_token_count", 0) or 0
    completion_tokens = getattr(usage_metadata, "candidates_token_count", 0) or 0
    return (prompt_tokens / 1_000_000 * GEMINI_TTS_USD_PER_1M_TEXT_INPUT
            + completion_tokens / 1_000_000 * GEMINI_TTS_USD_PER_1M_AUDIO_OUTPUT)


def compute_cost_usd(provider: str, model: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0) -> float:
    """0.0 for any model this table has no verified rate for -- never a guessed price. cached_tokens (added 2026-10-30) is billed at
    _CACHED_INPUT_RATE_PER_1M_USD when the model has one; the REMAINING (non-cached) input tokens still bill at the full input rate --
    cached_tokens must never exceed input_tokens (clamped) so a bad/duplicated usage read can't produce a negative "fresh" count."""
    rate = _RATES_PER_1M_USD.get(model)
    if rate is None:
        return 0.0
    input_rate, output_rate = rate
    cached_tokens = max(0, min(cached_tokens, input_tokens))
    cached_rate = _CACHED_INPUT_RATE_PER_1M_USD.get(model)
    fresh_input_tokens = input_tokens - cached_tokens
    cached_cost = (cached_tokens / 1_000_000) * cached_rate if cached_rate is not None else (cached_tokens / 1_000_000) * input_rate
    return (fresh_input_tokens / 1_000_000) * input_rate + cached_cost + (output_tokens / 1_000_000) * output_rate


def compute_asr_cost_usd(seconds_processed: float) -> float:
    """muse-voice-transcribe-1.0 cost for one push-to-talk utterance -- billed per whole second, rounded DOWN (per the
    pricing page's own "metered in whole seconds, rounded down" rule), so a one-off few-hundred-ms utterance can legitimately
    cost $0.0."""
    import math
    return math.floor(max(0.0, seconds_processed)) * MUSE_VOICE_TRANSCRIBE_USD_PER_SECOND
