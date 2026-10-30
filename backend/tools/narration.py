"""Deterministic, code-driven narration lines for the terminal pane (added 2026-10-30): the model's own prose is sometimes inconsistent
about announcing a phase transition (it can skip a step, or phrase it so differently the operator can't tell the pipeline is still on
track), so these fixed checkpoints are emitted directly from the tool code at the point each phase genuinely starts or ends, never left
to the model to remember to say. Shared by redteam_tools.py (clone/scan/active-pentest), sandbox_web_tools.py (server-component
check/install/start/stop), sandbox_tools.py (export/zip), doc_tools.py (Word report) and core.py (final time/cost).

Every call is best-effort and silent if ctx has no emit_terminal_progress (e.g. a CLI run, which has no terminal pane to write to)."""


async def narrate(ctx: dict, text: str) -> None:
    fn = ctx.get("emit_terminal_progress") if ctx else None
    if fn:
        await fn("aegis", text)
