"""The actual chat-loop logic, shared by the CLI (cli.py) and the web UI (web.py): picking a provider, dispatching tool calls, running one
user turn to completion. Callback-based (on_text/on_tool_call/on_terminal) instead of print() so either front end can render the same events
its own way -- stdout lines for the CLI, WebSocket messages for the web UI's two panes."""
import asyncio
import json
import os
import re

import time
import uuid
from datetime import datetime
from collections import Counter

from . import turnlog
from .llm import available_providers, chat, scan_fix_providers
from .model_pricing import compute_cost_usd
from .summary import deliverables_block, zap_summary
from .system_prompt import SYSTEM_PROMPT
from .tools.doc_tools import flush_pending_doc
from .tools_registry import DISPATCH, TOOL_SCHEMAS

MAX_ROUNDS = int(os.environ.get("AEGIS_MAX_ROUNDS", "200"))

# Same "fix/remediate/patch anywhere in the SAME message" rule the system prompt's own HARD RULES section tells the model to use for
# itself (scan-only vs. scan-and-fix) -- reused here so a personal scan/fix provider split (see llm.scan_fix_providers) routes each turn
# to the right model BEFORE the call even happens, not just as a prompt instruction the model could ignore.
_FIX_WORDS = re.compile(r"\b(fix|fixes|fixed|fixing|remediat\w*|patch|mitigat\w*|eliminat\w*|resolv\w*|repair\w*|harden\w*)\b", re.I)


class ProviderError(Exception):
    pass


# After a scan finishes, the model spends 10-15 s reading the results and writing the report before the Word document appears, with nothing
# visible happening in the chat pane. These short status lines (shown next to the working dots, replaced one by one, never kept as chat
# messages) cover that gap. They only run once a scan tool has finished in the turn, and stop the moment real text or the document arrives.
_SCAN_TOOLS = {"redteam_gitleaks", "redteam_bandit", "redteam_semgrep", "redteam_pip_audit", "redteam_npm_audit", "redteam_trivy", "pentest_zap",
               "pentest_lateral_movement"}
_FILLERS = ["Now reading through the scan results...",
            "Now sorting the findings by risk...",
            "Now checking every count against the scan...",
            "Now writing up the final report...",
            "Now creating the Word document for you...",
            "Now preparing your download link..."]
_FILLER_STEP_S = 2.5
_FILLER_DOC_STAGE = 4          # "creating the Word document" -- where she jumps to once the model has actually asked for the document


def get_current_datetime() -> str:
    """The real clock, as the JSON a tool result would carry. Run by code at the start and end of every user task and shown in the terminal."""
    now = datetime.now().astimezone()
    return json.dumps({"now": now.strftime("%Y-%m-%d %H:%M:%S"), "timezone": now.strftime("%Z") or now.strftime("%z"), "iso": now.isoformat(timespec="seconds")})


def _fmt_elapsed(seconds: float) -> str:
    total = int(round(seconds))
    return f"{total // 60} min, {total % 60} seconds"


class _Filler:
    def __init__(self, ctx, start=0):
        self.emit, self.i, self.task = ctx.get("emit_status"), start, None

    def start(self):
        if self.emit and self.task is None:
            self.task = asyncio.create_task(self._run())

    def jump(self, stage):
        self.i = max(self.i, stage)

    async def _run(self):
        try:
            await asyncio.sleep(1.0)
            while True:
                await self.emit(_FILLERS[min(self.i, len(_FILLERS) - 1)])
                if self.i >= len(_FILLERS) - 1:
                    await asyncio.sleep(3600)                                      # the last line just stays up until stop()
                self.i += 1
                await asyncio.sleep(_FILLER_STEP_S)
        except asyncio.CancelledError:
            pass
        except Exception:                                                         # noqa: BLE001 -- a status line must never break a turn
            pass

    async def stop(self):
        if self.task:
            self.task.cancel()
            self.task = None
            try:
                await self.emit("")                                                # clears the line
            except Exception:                                                     # noqa: BLE001
                pass


def pick_provider(requested: str = "", user_text: str = "") -> str:
    """requested (e.g. from AEGIS_PROVIDER, or the web UI's model dropdown) wins if it's actually configured. Otherwise, if the
    operator has set BOTH AEGIS_SCAN_PROVIDER and AEGIS_FIX_PROVIDER in .env (an opt-in personal choice, never a public
    default), user_text's own wording picks between them -- the same scan-vs-fix split the system prompt already asks the model to
    reason about for itself, just enforced structurally here too. Falls back to the first provider with a key present.
    Raises ProviderError with a message safe to show the end user."""
    requested = (requested or os.environ.get("AEGIS_PROVIDER", "")).strip().lower()
    avail = available_providers()
    if requested:
        if requested not in avail:
            raise ProviderError(f"{requested!r} is not configured on this host (no key set). Configured providers: {avail or 'none'}.")
        return requested
    scan_provider, fix_provider = scan_fix_providers()
    if scan_provider:
        return fix_provider if _FIX_WORDS.search(user_text or "") else scan_provider
    if not avail:
        raise ProviderError("No LLM provider is configured. Copy .env.example to .env and fill in at least one key, or set LOCAL_LLM_URL "
                             "for a local OpenAI-compatible server.")
    # "muse" wins the fallback whenever it's configured, even if gemini/claude keys also exist (added 2026-10-27:
    # GOOGLE_API_KEY got added for the Voice toggle's TTS, which is a COMPLETELY SEPARATE call path -- web.py's
    # /api/tts -- and must never make Gemini the actual CHAT engine on this Muse-only hackathon build. Before this
    # fix, avail[0] picked whichever PROVIDERS dict key happened to be configured first (gemini, before muse in
    # that dict's literal order), which silently swapped the entire chat provider the moment a Gemini key existed --
    # confirmed as a real regression the day GOOGLE_API_KEY was added for TTS). An explicit AEGIS_PROVIDER/dropdown
    # choice above still overrides this.
    return "muse" if "muse" in avail else avail[0]


def new_session() -> list:
    """A fresh message history, seeded with the system prompt."""
    return [{"role": "system", "content": SYSTEM_PROMPT}]


async def run_tool(name: str, args: dict, ctx: dict) -> str:
    fn = DISPATCH.get(name)
    if fn is None:
        return json.dumps({"ok": False, "error": f"unknown tool {name!r}"})
    try:
        return await fn(args, ctx)
    except Exception as e:                                                        # noqa: BLE001 -- a tool crashing must never kill the whole session
        return json.dumps({"ok": False, "error": f"the tool raised {type(e).__name__}: {e}"})


async def run_turn(provider: str, messages: list, ctx: dict, on_text, on_tool_call) -> None:
    """Runs one user turn to completion: repeatedly calls the LLM, dispatches whatever tools it asks for, and appends everything to
    `messages` in place, until it answers with no tool calls or MAX_ROUNDS is hit.
    on_text(text) -- AWAITED with each non-empty assistant text chunk (the CLI prints it; the web UI sends a chat WebSocket message).
    on_tool_call(name, args, result) -- AWAITED after each tool call completes (the CLI prints a one-line summary; the web UI sends
    terminal lines for the live terminal pane). Both must be async callables (`async def`, not a plain function) -- awaited directly here
    so every message reaches its destination in the exact order it happened, never fire-and-forget.
    Every LLM round's real token usage is priced (model_pricing.compute_cost_usd) and added to ctx["session_cost_usd"] (created at 0.0 if
    not already present) -- a running total across the WHOLE session, not just this turn, so the caller can read it back after run_turn
    returns and show it next to the model picker, same idea as the full-featured version's session-cost readout.
    Raises ProviderError (from llm.chat) straight through -- the caller decides how to surface it."""
    ctx.setdefault("session_cost_usd", 0.0)
    ctx["turn_no"] = ctx.get("turn_no", 0) + 1
    sid, turn_id = ctx.setdefault("sid", uuid.uuid4().hex[:6]), f"{ctx['turn_no']}"
    last_user = next((m.get("content", "") for m in reversed(messages) if m.get("role") == "user"), "")
    turnlog.log("turn_start", sid=sid, turn=turn_id, provider=provider, user_chars=len(str(last_user)), user_preview=turnlog.scrub(last_user, 90),
                history_msgs=len(messages))
    wall0, llm_s, tool_s = time.monotonic(), 0.0, 0.0
    is_task = not ctx.get("greeting")
    # A task that asks for a FIX (fix / remediate / patch / mitigate in this message, or a short "continue" / "yes" right after one) is not a plain scan:
    # the model writes its own closing message about what it fixed, and the report is not given the scan-only verdict section.
    if _FIX_WORDS.search(str(last_user)):
        ctx["fix_task"] = True
    elif not re.fullmatch(r"\s*(continue|yes\b.*|ok\b.*|okay\b.*|go on|go ahead|proceed|do it|please do)[.! ]*", str(last_user), re.I):
        ctx["fix_task"] = False
    if is_task:
        ctx["task_t0"] = wall0
        started = get_current_datetime()
        _st = json.loads(started)
        ctx["task_started"] = f"{_st['now']} {_st['timezone']}"
        ctx["task_cost0"] = ctx.get("session_cost_usd", 0.0)
        ctx["task_asrtts0"] = ctx["_asr_tts_cost_fn"]() if ctx.get("_asr_tts_cost_fn") else 0.0
        await on_tool_call("get_current_datetime", {}, started)
    tok_in = tok_out = 0
    cost0 = ctx["session_cost_usd"]
    tool_counts, seen_calls, repeats, tool_errors, rounds = Counter(), Counter(), 0, 0, 0
    end_reason = "max_rounds"
    # Structural guard against a real, repeated failure (sagemaker-python-sdk, microsoft/TokenEconomizer,
    # aws/tools-for-devops-agent, 2026-10-28/29): on a fix task with many findings, the model sometimes spends many
    # rounds triaging (reading flagged lines one at a time) then ends the turn with a detailed triage summary as
    # its final answer -- zero edit_file calls, despite being asked to fix. A prompt-only rule already exists for
    # the sibling bug (ending with "want me to keep going?") but this version ends with NO question at all, so it
    # slips past that wording. Tracked per-turn (reset here, not session-wide like ctx["scan_done"]) so a nudge
    # is only considered for THIS turn's own findings/fixes, never carried over from an earlier turn.
    turn_findings_total = 0
    turn_edit_calls = 0
    turn_export_ok = False
    fix_nudge_count = 0
    FIX_NUDGE_MAX = 2   # one for "never fixed anything", one for "fixed but never exported/reported" -- bounded, not unlimited


    def _task_cost() -> float:
        """LLM reasoning cost for THIS task plus any ASR (push-to-talk transcription) and TTS (spoken reply) cost
        accrued during it -- matches what the header's grand-total readout counts, so the chat line/report footer
        and the header never disagree about what one task actually cost (found live 2026-10-28: the per-task figure
        was LLM-only, silently excluding real ASR/TTS spend the header already included)."""
        llm = max(0.0, ctx["session_cost_usd"] - ctx.get("task_cost0", cost0))
        asrtts = max(0.0, (ctx["_asr_tts_cost_fn"]() if ctx.get("_asr_tts_cost_fn") else 0.0) - ctx.get("task_asrtts0", 0.0))
        return llm + asrtts

    async def _closing(text: str) -> str:
        """Final step of a user task: the terminal clock line, then the held Word report and the completion line from the SAME two numbers
        (measured here by code, never by the model), so the report footer and the chat line always match."""
        await on_tool_call("get_current_datetime", {}, get_current_datetime())
        elapsed, task_cost = time.monotonic() - wall0, _task_cost()
        await flush_pending_doc(ctx, elapsed, task_cost, provider)
        block = deliverables_block(ctx)
        text = (text.rstrip() + ("\n\n" + block if block else "")) if block else text
        return text.rstrip() + f"\n\n**Completed task in:** {_fmt_elapsed(elapsed)}. **Total cost:** ${task_cost:.3f}, **Model:** {provider}"
    try:
        for _round_no in range(MAX_ROUNDS):
            rounds += 1
            t0 = time.monotonic()
            # While the closing message is being written after the report was accepted, the last "preparing your download link" line stays up.
            filler = _Filler(ctx, start=len(_FILLERS) - 1 if ctx.get("pending_doc") else 0)
            if ctx.get("scan_done") and (not ctx.get("doc_done") or ctx.get("pending_doc")):
                filler.start()
            try:
                # repo_visibility is None before ANY scoped tool call has happened this session (the greeting's check_scanner_versions
                # and verify_sandbox_safety fire here -- unscoped, no target/project, nothing sensitive could have been sent yet) --
                # treat that the same as "public" for billing-tier purposes. It flips to "private" (sticky) the moment a scoped call
                # actually names something not confirmed public, per the fail-closed logic below; from then on this condition is false.
                model_override = ("muse-spark-1.3-contributor" if provider == "muse" and ctx.get("repo_visibility") in ("public", None) else "")
                text, calls, usage = await chat(provider, messages, TOOL_SCHEMAS, model_override)
                if any(c["name"] == "create_word_document" for c in calls):
                    filler.jump(_FILLER_DOC_STAGE)
                else:
                    await filler.stop()
            except BaseException:
                await filler.stop()
                raise
            round_llm_s = time.monotonic() - t0
            llm_s += round_llm_s
            round_cost = compute_cost_usd(provider, usage.get("model", ""), usage.get("input_tokens", 0), usage.get("output_tokens", 0))
            ctx["session_cost_usd"] += round_cost
            tok_in += usage.get("input_tokens", 0)
            tok_out += usage.get("output_tokens", 0)
            turnlog.log("round", sid=sid, turn=turn_id, n=rounds, model=usage.get("model", ""), in_tok=usage.get("input_tokens", 0),
                        out_tok=usage.get("output_tokens", 0), cost_usd=round(round_cost, 5), llm_s=round(round_llm_s, 2), text_chars=len(text or ""),
                        tools=[c["name"] for c in calls])
            if not calls and is_task:
                text = await _closing(text or "")
            if text:
                await filler.stop()
                await on_text(text)
            if not calls:
                doc_made_this_turn = ctx.get("doc_made_turn") == ctx.get("turn_no")
                deliverable_gap = None
                if is_task and ctx.get("fix_task") and turn_findings_total > 0 and fix_nudge_count < FIX_NUDGE_MAX:
                    if turn_edit_calls == 0:
                        deliverable_gap = (
                            f"You have not called edit_file yet, but {turn_findings_total} real finding(s) were found "
                            "this turn and a fix was asked for. Triage is not a fix -- the operator asked for 0 findings "
                            "left, not an assessment. Call edit_file now with the real fixes for these findings, batched "
                            "by finding class, then re-scan, export, and report, same as every other fix job. Do not end "
                            "this turn with any finding still unfixed."
                        )
                    elif not turn_export_ok or not doc_made_this_turn:
                        # Real gap, found live 2026-10-29 right after the edit_file guard above shipped: on
                        # microsoft/TokenEconomizer and aws/tools-for-devops-agent, the model DID call edit_file
                        # (the first guard worked) but then stopped before export_project/create_word_document --
                        # same silent-stop pattern, one stage later. "fixed but never packaged/reported" is just
                        # as incomplete as "never fixed," so it gets the same structural nudge.
                        missing = [n for n, done in (("export_project", turn_export_ok), ("create_word_document", doc_made_this_turn)) if not done]
                        deliverable_gap = (
                            f"You called edit_file this turn but never finished the job -- {' and '.join(missing)} "
                            "still has not run. A fix job is not done until the fixed code is exported AND the Word "
                            "report is created, same as every other fix job. Call whichever of these is still "
                            "missing now, in this same turn -- do not end with the job half-delivered."
                        )
                if deliverable_gap:
                    fix_nudge_count += 1
                    turnlog.log("fix_nudge", sid=sid, turn=turn_id, findings=turn_findings_total, round=rounds,
                                nudge_n=fix_nudge_count, edit_calls=turn_edit_calls, export_ok=turn_export_ok, doc_done=doc_made_this_turn)
                    messages.append({"role": "assistant", "content": text, "tool_calls": []})
                    messages.append({"role": "user", "content": deliverable_gap})
                    continue
                end_reason = "answered"
                return
            messages.append({"role": "assistant", "content": text, "tool_calls": calls})
            for tc in calls:
                sig = (tc["name"], json.dumps(tc["arguments"], sort_keys=True, default=str))
                seen_calls[sig] += 1
                is_repeat = seen_calls[sig] > 1
                repeats += is_repeat
                t1 = time.monotonic()
                result = await run_tool(tc["name"], tc["arguments"], ctx)
                # Which Muse Spark billing tier is safe for this session's content -- FAIL-CLOSED (fixed 2026-10-27, a real gap found
                # before this shipped anywhere else): contributor (10x cheaper, Meta CAN train on it) is only ever used once a target name
                # is CONFIRMED public, never on the mere fact that redteam_clone_repo was called. Two real bugs this closes:
                #   1. redteam_clone_repo can answer ok:false (e.g. a private repo someone tried without a token) -- that must NOT flip
                #      visibility to "public", or the next round bills a failed-private-clone attempt (its URL now in history) at the
                #      training-tier rate.
                #   2. "self" (this codebase) was never explicitly marked private -- clone a public repo, then scan "self" in the SAME
                #      session, and self's own source would go out on the contributor tier, directly contradicting the disclosure message.
                # ctx["public_targets"]: the set of clone names actually confirmed public (ok:true from redteam_clone_repo). Any OTHER
                # scoped tool call (one that takes a target/project argument -- the scanners, sandbox_app_*, export_project) whose
                # target/project is NOT in that set -- "self" included -- flips repo_visibility to "private", sticky for the rest of the
                # session, same as an explicit redteam_clone_private_repo call. Unscoped tools (bash_run, edit_file, repl_run,
                # create_word_document, check_scanner_versions) cannot be verified safe and are left to whatever the last scoped call set.
                public_targets = ctx.setdefault("public_targets", set())
                if tc["name"] == "redteam_clone_repo":
                    try:
                        parsed = json.loads(result)
                    except ValueError:
                        parsed = {}
                    if parsed.get("ok") and parsed.get("name"):
                        public_targets.add(parsed["name"])
                        if ctx.get("repo_visibility") != "private":
                            ctx["repo_visibility"] = "public"
                elif tc["name"] == "redteam_clone_private_repo":
                    ctx["repo_visibility"] = "private"
                else:
                    tgt = tc["arguments"].get("target") or tc["arguments"].get("project")
                    # Prefix match, not exact match (fixed 2026-10-27): export_project names the fixed copy
                    # "<clone-name>-fixed" (or similar), which is still the SAME confirmed-public content --
                    # an exact-match-only check was flipping the last few rounds of every public run (the
                    # export + report rounds) to the pricier Standard tier for no real safety reason, a real
                    # cost-inefficiency confirmed in two live Muse runs. A target can only match this way if it
                    # is exactly a known-public name or starts with "<name>-"/"<name>_" -- "self" and any
                    # genuinely different target still fail closed, since no public_targets entry is a prefix
                    # of those.
                    if tgt is not None and not any(tgt == t or tgt.startswith(t + "-") or tgt.startswith(t + "_") for t in public_targets):
                        ctx["repo_visibility"] = "private"
                if tc["name"] in _SCAN_TOOLS:
                    ctx["scan_done"] = True
                    try:
                        turn_findings_total += json.loads(result).get("count") or 0
                    except (ValueError, TypeError, AttributeError):
                        pass
                elif tc["name"] == "edit_file":
                    turn_edit_calls += 1
                elif tc["name"] == "export_project":
                    try:
                        turn_export_ok = turn_export_ok or bool(json.loads(result).get("ok"))
                    except (ValueError, TypeError, AttributeError):
                        pass
                elif tc["name"] == "create_word_document" and '"created": true' in result:
                    ctx["doc_done"] = True
                    ctx["doc_made_turn"] = ctx.get("turn_no")
                dt = time.monotonic() - t1
                tool_s += dt
                info = turnlog.summarize_result(result)
                failed = info.get("ok") is False or bool(info.get("error"))
                tool_errors += failed
                tool_counts[tc["name"]] += 1
                turnlog.log("tool", sid=sid, turn=turn_id, round=rounds, name=tc["name"], args=turnlog.summarize_args(tc["name"], tc["arguments"]),
                            s=round(dt, 2), repeat=is_repeat, failed=failed, **info)
                await on_tool_call(tc["name"], tc["arguments"], result)
                messages.append({"role": "tool", "tool_call_id": tc["id"], "content": result})
            await filler.stop()
            if is_task and not ctx.get("fix_task") and ctx.get("pending_doc") and (ctx.get("last_zap") or {}).get("turn") == ctx["turn_no"]:
                # An active-ZAP task whose report was accepted: the closing message is written by code from the scan result (identical for
                # every model, nothing invented) and the model's own closing call is skipped.
                await on_text(await _closing(zap_summary(ctx["last_zap"])))
                end_reason = "answered_by_code"
                return
        await on_text(f"[stopped after {MAX_ROUNDS} rounds without a final answer -- say \"continue\" to keep going.]")
    except BaseException as e:                                                    # noqa: BLE001 -- recorded, then re-raised unchanged
        end_reason = f"error:{type(e).__name__}"
        raise
    finally:
        if ctx.get("pending_doc"):                                                # the turn ended early (error / round cap): still deliver the report
            try:
                await flush_pending_doc(ctx, time.monotonic() - wall0, _task_cost(), provider)
            except Exception:                                                     # noqa: BLE001
                pass
        turnlog.log("turn_end", sid=sid, turn=turn_id, reason=end_reason, rounds=rounds, tool_calls=sum(tool_counts.values()), tools=dict(tool_counts),
                    repeated_calls=repeats, failed_calls=tool_errors, llm_s=round(llm_s, 1), tools_s=round(tool_s, 1),
                    wall_s=round(time.monotonic() - wall0, 1), in_tok=tok_in, out_tok=tok_out,
                    turn_cost_usd=round(ctx["session_cost_usd"] - cost0, 4), session_cost_usd=round(ctx["session_cost_usd"], 4))
