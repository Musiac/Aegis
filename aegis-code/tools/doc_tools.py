"""create_word_document -- a real downloadable report, same end-user shape as the full-featured version's tool: the model writes title + body (light
markdown: #/##/### headings, -/*/numbered bullets, plain paragraphs), this builds a real .docx in memory and delivers it through
ctx["emit_document"] as {"kind","filename","mime","size","data_base64","created_at"} -- the web UI turns that into a download card
(see web.py/app.js), the CLI writes it straight to a file on disk. Deliberately simpler than the full-featured version's build_docx: no PDF/PPTX/XLSX
siblings, no tables, no bold/italic inline parsing -- Aegis's reports are scan/fix summaries, not rich documents."""
import base64
import io
import json
import time
import re
from datetime import datetime, timezone

from .. import turnlog
from .narration import narrate

_MAX_BODY_CHARS = 200_000


def _real_date_line(body: str, ctx: dict) -> str:
    """The model writes a 'Date:' line from memory and got it wrong (2026-05-24 in a report made on 2026-10-26). The date is the machine's, written by code."""
    from datetime import datetime
    today = datetime.now().astimezone().strftime("%Y-%m-%d")
    return re.sub(r"(?im)^[ \t]*\**[ \t]*date[ \t]*:?[ \t]*\**[ \t]*:?[ \t]*\d{4}-\d{2}-\d{2}[^\n]*$", f"**Date:** {today}", body)


def _build_docx(title: str, body: str) -> bytes:
    from docx import Document

    from .. import docx_md

    doc = Document()
    if title:
        h = doc.add_heading(title, level=0)
        h.alignment = 0
    docx_md.add_markdown(doc, body, _MAX_BODY_CHARS)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _count_problems(title: str, body: str, ctx: dict) -> list:
    """Checks a pentest report's numbers against the ZAP result this session actually returned (ctx["last_zap"], set in redteam_tools._finish).
    A model can write a plausible total or drop one rule while grouping; this is the code-level backstop that catches it. Only applies to a
    report about a ZAP scan, and only when the scan result was not truncated (when it was, per-rule instance counts are not fully known)."""
    zap = ctx.get("last_zap")
    text = f"{title}\n{body}"
    if not zap or zap.get("truncated") or not re.search(r"\bZAP\b|pentest", text, re.I):
        return []
    problems = []
    m = re.search(r"Total findings\W{0,8}(\d+)", body, re.I)
    if m and int(m.group(1)) != zap["total"]:
        problems.append(f"the report says Total findings {m.group(1)} but the scan returned {zap['total']}")
    elif not m:
        problems.append(f"the report has no 'Total findings: {zap['total']}' line (copy summary.total exactly)")
    for r in zap.get("by_rule", []):
        # the instance count may be written "(9)" after the rule name or as the last cell of a pipe-table row "| 10021 | name | Low | 9 |"
        shown = None
        for line in body.splitlines():
            if re.search(rf"\b{re.escape(str(r['rule']))}\b", line):
                cm = re.search(r"\((\d+)\)", line) or re.search(r"\|\s*(\d+)\s*\|?\s*$", line.strip())
                if cm:
                    shown = int(cm.group(1))
                    break
        if shown is None:
            problems.append(f"rule {r['rule']} ({r['name']}, {r['instances']} instance(s)) is missing from the report, or has no instance count")
        elif shown != r["instances"]:
            problems.append(f"rule {r['rule']} is shown with {shown} instances but the scan returned {r['instances']}")
    return problems


async def create_word_document(args: dict, ctx: dict) -> str:
    """Builds a real .docx and delivers it to the current session -- call this once the work a request asked for is actually done (the
    scan, or the scan + any fix), same as the full-featured version's skills always do. title + body only; body is light markdown (#/##/###
    headings, -/* or numbered bullets, plain paragraphs)."""
    title = str(args.get("title") or "").strip()[:150]
    body = str(args.get("body") or "")
    if not (title or body.strip()):
        return json.dumps({"created": False, "error": "There is nothing to put in the document yet -- pass a title and/or body."})
    problems = _count_problems(title, body, ctx)
    if problems:
        ctx["doc_count_rejects"] = ctx.get("doc_count_rejects", 0) + 1
        turnlog.log("count_check", sid=ctx.get("sid"), result="rejected", attempt=ctx["doc_count_rejects"], problems=problems)
        if ctx["doc_count_rejects"] < 3:
            return json.dumps({"created": False, "error": "The numbers in this report do not match the scan result: " + "; ".join(problems) + ". "
                                "Rewrite the report using ONLY these exact values and call create_word_document again: Total findings = "
                                f"{ctx['last_zap']['total']}; per rule (id, name, instances) = "
                                + ", ".join(f"{r['rule']} {r['name']} ({r['instances']})" for r in ctx["last_zap"]["by_rule"]) + "."})
        # Third try and still off: never silently ship wrong numbers -- ship the report with a visible warning on top instead of blocking forever.
        body = ("WARNING: the counts in this report could not be verified against the scan result (" + "; ".join(problems) + "). "
                f"The scan itself returned {ctx['last_zap']['total']} findings.\n\n") + body
    elif ctx.get("last_zap"):
        turnlog.log("count_check", sid=ctx.get("sid"), result="ok", total=ctx["last_zap"]["total"], rules=len(ctx["last_zap"].get("by_rule", [])))
    if ctx.get("task_t0") is not None:
        # Held back and built AFTER the model's final chat message, so the footer carries the same final time and cost as the chat line
        # (core.run_turn calls flush_pending_doc). A second call in the same task replaces the first.
        ctx["pending_doc"] = {"title": title, "body": body}
        return json.dumps({"created": True, "pending": True,
                           "note": "The report is accepted and will be attached to the operator's screen together with your reply. Now write your ONE "
                                   "short closing message: say the report is ready to download and offer to change something. Do not paste its content."})
    return await _deliver(title, body, ctx)


async def flush_pending_doc(ctx: dict, elapsed_s: float, cost_usd: float, provider: str = "") -> None:
    """Builds and sends the report held by create_word_document, with a footer written by code from the SAME elapsed time and cost the chat
    line shows. No-op when nothing is held."""
    pd = ctx.pop("pending_doc", None)
    if not pd:
        return
    secs = int(round(elapsed_s))
    z = ctx.get("last_zap") or {}
    if z.get("turn") == ctx.get("turn_no") and not ctx.get("fix_task"):
        # Same verdict and per-finding list as the chat summary, written by code and placed first.
        from ..summary import zap_summary
        pd["body"] = "## Verdict and findings\n" + zap_summary(z, plain=True) + "\n\n" + pd["body"]
    body = pd["body"].rstrip() + (f"\n\nTask started: {ctx.get('task_started', '')}. Completed task in: {secs // 60} min, {secs % 60} seconds "
                                  f"(end-to-end). Total run cost: ${cost_usd:.3f}" + (f", Model: {provider}" if provider else ""))
    res = await _deliver(pd["title"], body, ctx)
    if '"created": true' not in res:
        turnlog.log("doc_flush_failed", sid=ctx.get("sid"), result=turnlog.scrub(res, 160))
    await narrate(ctx, f"Total time: {secs // 60} min {secs % 60} sec. Total cost: ${cost_usd:.3f}" + (f" ({provider})." if provider else "."))


async def _deliver(title: str, body: str, ctx: dict) -> str:
    await narrate(ctx, "Now creating the Word document summarizing the complete process.")
    data = _build_docx(title, _real_date_line(body, ctx))
    if len(data) > 8 * 1024 * 1024:
        return json.dumps({"created": False, "error": "The document came out too large to send (over 8 MB). Ask for a shorter report."})
    safe_title = re.sub(r"[^A-Za-z0-9_-]+", "_", title or "report").strip("_")[:60] or "report"
    filename = f"{safe_title}_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%S')}.docx"
    emit_document = ctx.get("emit_document")
    if not emit_document:
        return json.dumps({"created": False, "error": "This session cannot show files."})
    doc_b64 = base64.b64encode(data).decode("ascii")
    await emit_document({"kind": "docx", "filename": filename, "mime": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                          "size": len(data), "data_base64": doc_b64,
                          "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"})
    # Also land this SAME report inside the project's already-exported zip, if one exists this session (added 2026-10-30, a real gap:
    # the browser-delivered download above is the only copy of the report today -- a driver script or any client that doesn't persist
    # the websocket's data_base64 payload loses the report entirely once the session closes, even though CHANGES.txt/the fixed code
    # survives fine in the zip). Best-effort and silent on failure -- this must never block or alter the real delivery above.
    last_export = ctx.get("last_export") or {}
    if last_export.get("path"):
        from .sandbox_tools import append_doc_to_export
        try:
            append_result = await append_doc_to_export(str(last_export["path"]), filename, doc_b64)
            if append_result.get("ok"):
                await narrate(ctx, f"Word document added to the zip file at {last_export['path']}, alongside the fixed repo and CHANGES.txt.")
        except Exception:                                                        # noqa: BLE001
            pass
    from .sandbox_web_tools import ensure_stopped_after_report
    stop_note = await ensure_stopped_after_report(ctx)       # the one guaranteed point: a sandboxed app started earlier this turn is stopped HERE, in
                                                              # code, whatever the model did or didn't call itself (see sandbox_web_tools._mark_running)
    return json.dumps({"created": True, "filename": filename, "size_kb": round(len(data) / 1024),
                        "note": ("The file is now available to the operator as a download. Say so in ONE short sentence and offer to "
                                 "change something. Do not read the document aloud and do not paste its content."
                                 + (f" {stop_note}" if stop_note else ""))})
