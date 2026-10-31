"""The closing chat message for an active-ZAP task, written by code from the scan's own result so every model (gpt, local, ...) gives the same
answer and nothing in it can be invented. It also saves the last model call of the task. Only facts the scan returned are used: counts,
severity, rule, name and relative URL per finding, and whether the active scan ran."""
_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


def _clean(s) -> str:
    return str(s or "").replace("`", "'").replace("\n", " ").strip()


def zap_summary(z: dict, plain: bool = False) -> str:
    """plain=True is the Word-document version: same facts, no Markdown bold/backticks (the document builder does not render them)."""
    b = (lambda t: t) if plain else (lambda t: f"**{t}**")
    c = (lambda t: t) if plain else (lambda t: f"`{t}`")
    findings = [f for f in (z.get("findings") or []) if isinstance(f, dict)]
    total = z.get("total", len(findings))
    lines = [b(f"Active OWASP ZAP pentest of {_clean(z.get('target'))}: {z.get('tally_sentence') or str(total) + ' total'}"), ""]
    categories = [_clean(c) for c in (z.get("tested_categories") or []) if c]
    if categories:
        lines.append(f"Tested for: {', '.join(categories)}.")
    if not z.get("active_scan_ran"):
        lines.append("The active scan did " + b("not") + " run, so this is a crawl and passive check only. Treat it as incomplete.")
    elif any(str(f.get("risk")) == "High" for f in findings):
        lines.append(b("ZAP reported High-risk findings") + " -- these need attention first.")
    elif total == 0:
        lines.append("ZAP's active scan ran and reported no findings.")
    else:
        lines.append("ZAP's active scan ran and reported no High-risk findings.")
    if findings:
        lines.append("")
        for f in sorted(findings, key=lambda f: (_ORDER.get(str(f.get("risk")), 9), str(f.get("rule")), str(f.get("url")))):
            lines.append(f"- {b(_clean(f.get('risk')) or 'Unrated')} -- {_clean(f.get('name'))} (rule {_clean(f.get('rule'))}) -- {c(_clean(f.get('url')) or '/')}")
        if total > len(findings):
            lines.append(f"- ...only the first {len(findings)} of {total} are listed.")
    if plain:
        return "\n".join(lines)
    lines += ["", "The Word report is ready to download above."]
    if total:
        lines.append("I can help fix these -- just say so and tell me which code or repo to work in.")
    return "\n".join(lines)


# Where the zip really is on the operator's machine. The sandbox writes it to /aegis_out, which is a bind mount of this folder on the host, so it
# survives container restarts. The container cannot see the host path, so it is configured (AEGIS_OUT_HOST_DIR) with this default for the Mac install.
OUT_HOST_DIR = "/Users/bhaweshsingh/GenAI/Aegis/aegis_out"


def deliverables_block(ctx: dict) -> str:
    """The 'what I made and where it is' lines for the end of a fix task, from what the tools really did this turn (never from the model's say-so)."""
    import os
    ex = ctx.get("last_export")
    if not ex or ex.get("turn") != ctx.get("turn_no") or not ex.get("filename"):
        return ""
    host_dir = os.environ.get("AEGIS_OUT_HOST_DIR", OUT_HOST_DIR).rstrip("/")
    lines = ["**What I made**"]
    doc_made_this_turn = ctx.get("doc_made_turn") == ctx.get("turn_no")
    if doc_made_this_turn:
        lines.append("- **Word report:** ready to download with the button above -- also saved INSIDE the zip below (added 2026-10-30), "
                      "so it's never lost even if this download is never saved anywhere.")
    lines.append(f"- **Zip of the fixed code:** `{host_dir}/{ex['filename']}` -- on the host filesystem, outside the container, so it survives container restarts.")
    if ex.get("has_changes"):
        detail = f" ({ex['files']} file(s) changed, +{ex['plus']} / -{ex['minus']} lines)" if ex.get("files") is not None else ""
        lines.append(f"- **`CHANGES.txt`**{detail} is inside the zip: the before/after diff of every file I changed.")
    else:
        lines.append("- `CHANGES.txt` could not be built this time, so the zip has no diff file.")
    return "\n".join(lines)
