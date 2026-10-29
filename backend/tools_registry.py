"""The tool registry: OpenAI-style function schemas (also translated for Claude by llm.py) plus the dispatch table mapping each tool name to
the real async function in backend/tools/*.py that runs it. The chat loop (cli.py) never imports a tools/*.py module directly -- it goes
through REGISTRY so adding a tool means adding one entry here, nothing else."""
from .tools import doc_tools, pentest_tools, redteam_tools, sandbox_tools, sandbox_verify, sandbox_web_tools

TOOL_SCHEMAS = [
    {
        "name": "redteam_clone_repo",
        "description": "Clones a git repo (public or private) FRESH from GitHub into the dynamic target pool. "
                        "CRITICAL: When the operator gives an explicit GitHub URL, ALWAYS clone it from GitHub, even if the URL "
                        "points to Aegis's own repository -- the operator wants to scan the CURRENT GitHub state, not local code. "
                        "NEVER substitute 'self' when given a URL. Only scan 'self' when the operator explicitly says 'scan self' "
                        "or 'scan your own code' WITHOUT providing a URL. "
                        "For PUBLIC repos, just provide the URL. For PRIVATE repos, this will detect it and guide you to use "
                        "redteam_clone_private_repo with a token file. Call this FIRST whenever the operator names a repo URL -- "
                        "it returns the target NAME to use for every later redteam_*/export_project call.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "The git repo URL (https://github.com/owner/repo or git@github.com:owner/repo)."},
            "name": {"type": "string", "description": "Optional target name to use instead of the auto-derived owner_repo slug."},
        }, "required": ["url"]},
    },
    {
        "name": "redteam_clone_private_repo",
        "description": "Clones a PRIVATE git repository using a GitHub Personal Access Token from a file. Use this ONLY after "
                        "redteam_clone_repo tells you a repo is private and asks for authentication. The token is read once and not stored.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "The GitHub repository URL (https://github.com/owner/repo)."},
            "token_file": {"type": "string", "description": "Full absolute path to a file containing the GitHub PAT (e.g., /home/ubuntu/token.txt)."},
            "name": {"type": "string", "description": "Optional target name to use instead of the auto-derived owner_repo slug."},
        }, "required": ["url", "token_file"]},
    },
    *[
        {
            "name": f"redteam_{tool}",
            "description": f"Runs {tool} (a real static scanner, not a description) against `target` -- \"self\" (Aegis's own source) "
                            "or the name redteam_clone_repo returned for a cloned repo. Returns the exact count and findings list.",
            "parameters": {"type": "object", "properties": {
                "target": {"type": "string", "description": "\"self\", or the target name redteam_clone_repo returned."},
            }, "required": ["target"]},
        }
        for tool in ("gitleaks", "bandit", "semgrep", "pip_audit", "npm_audit")
    ],
    {
        "name": "redteam_trivy",
        "description": "Scans one of Aegis's own built container images (target: \"redteam\", \"sandbox\", \"pentestlive\" or \"backend\") "
                        "for known-CVE vulnerabilities and leaked secrets baked into image layers. install.sh builds and saves these tarballs "
                        "itself -- if a target is not available, say so plainly rather than guessing a different name.",
        "parameters": {"type": "object", "properties": {"target": {"type": "string", "description": "redteam, sandbox, pentestlive or backend."}}, "required": ["target"]},
    },
    {
        "name": "pentest_zap",
        "description": "Spider + passive + ACTIVE (attacking) OWASP ZAP scan against target_url -- a target the OPERATOR has stood up "
                        "themselves and names explicitly. Naming a URL here at all is the operator's own scoped consent; the only thing "
                        "refused regardless of intent is the cloud-metadata address. This sends real payloads, not pattern matches -- say so "
                        "before calling it, and that it can take a few minutes.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string", "description": "The full http(s) URL to attack, e.g. http://localhost:8080/."},
        }, "required": ["target_url"]},
    },
    {
        "name": "pentest_lateral_movement",
        "description": "ethical_hack skill ONLY: measures the real difference between an unauthenticated crawl of target_url and an "
                        "authenticated crawl using session_cookie (a real 'name=value' cookie you captured by logging in through your own "
                        "deliberate auth-bypass patch), then actively scans the newly-reachable pages. Call this only AFTER you have patched "
                        "the target's auth check, restarted the sandboxed server, and actually logged in -- never with a made-up cookie.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string", "description": "The running sandboxed app's URL, e.g. http://www.sandbox.com:8900/."},
            "session_cookie": {"type": "string", "description": "A real captured 'name=value' session cookie from a login response."},
        }, "required": ["target_url", "session_cookie"]},
    },
    {
        "name": "pentestlive_consent",
        "description": "Records the operator's explicit, typed decision to run an ACTIVE pentest probe against ONE real target_url that is "
                        "NOT something they stood up themselves (a real third-party site). `typed` must be exactly the word PENTESTLIVE, "
                        "typed by the operator -- never accept \"yes\"/\"go ahead\"/anything else, and never fill the word in yourself.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "typed": {"type": "string", "description": "Exactly what the operator typed -- pass it through verbatim, never invent it."},
        }, "required": ["target_url", "typed"]},
    },
    {
        "name": "pentestlive_scan",
        "description": "Runs ONE active probe (liveness + technology detection, no templates, no fuzzing) against target_url. Refuses unless "
                        "pentestlive_consent already recorded a matching consent THIS session for the same target_url.",
        "parameters": {"type": "object", "properties": {
            "target_url": {"type": "string"},
            "username": {"type": "string", "description": "Optional HTTP Basic Auth username."},
            "password": {"type": "string", "description": "Optional HTTP Basic Auth password."},
        }, "required": ["target_url"]},
    },
    {
        "name": "verify_sandbox_safety",
        "description": "Runs 3 REAL checks against the live sandbox container -- not assertions, actual commands -- to prove its "
                        "isolation guarantees before doing any real work in it: (1) a write/delete attempt outside the sandbox's "
                        "writable paths, (2) a real network request to an external site, (3) the real memory/process/CPU caps the "
                        "host enforces on it. Call this ONCE, right after the sandbox is confirmed up (the first bash_run or "
                        "sandbox_app_start of a session), before cloning, fixing, or scanning anything -- report each check's real "
                        "result plainly in chat as it runs, in your own words, not as a raw dump.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "bash_run",
        "description": "Runs a bash command in the isolated sandbox (python, uv, coreutils, grep, sed, awk, jq, git, curl). Working directory "
                        "and exported shell variables carry over between calls. This is how fixredteam/fixpentest read and edit a target's "
                        "working copy: /self_target/self for \"self\", /dynamic_target/<name> for a cloned repo.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string"},
            "timeout": {"type": "integer", "description": "Seconds, default 20, max 45."},
        }, "required": ["command"]},
    },
    {
        "name": "edit_file",
        "description": "Replaces exact text in ONE file inside a working copy (/dynamic_target/<name>/..., /self_target/self/..., /REPL/work/...). "
                        "USE THIS for every code edit instead of writing a python/sed patch script through bash_run: there is no shell quoting to get "
                        "wrong. old_text must match the file exactly (copy it from the lines you read) and must be unique, or pass replace_all. "
                        "To add new code, use the neighbouring existing line as old_text and put it back inside new_text with your addition.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "old_text": {"type": "string"},
            "new_text": {"type": "string"},
            "replace_all": {"type": "boolean"},
            "edits": {"type": "array", "description": "SEVERAL edits in ONE call (preferred when you have more than one): a list of "
                      "{path, old_text, new_text, replace_all}, applied in order. Use this instead of one edit_file call per round.",
                      "items": {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"},
                                                                  "new_text": {"type": "string"}, "replace_all": {"type": "boolean"}},
                                "required": ["path", "old_text", "new_text"]}},
        }, "required": []},
    },
    {
        "name": "repl_run",
        "description": "Runs Python 3.12 in the isolated sandbox and returns what it printed.",
        "parameters": {"type": "object", "properties": {
            "code": {"type": "string"},
            "name": {"type": "string", "description": "Optional: save as /REPL/<name>.py instead of a throwaway scratch file."},
            "timeout": {"type": "integer", "description": "Seconds, default 20, max 45."},
        }, "required": ["code"]},
    },
    {
        "name": "repl_list",
        "description": "Lists the scripts already saved in /REPL. Check this before writing new code.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "sandbox_app_start",
        "description": "Starts the REAL web server of a cloned (or self) project at http://www.sandbox.com:8900/, reachable from pentest_zap -- "
                        "the missing piece for 'start the cloned code's server and pentest it'. Stops whatever app was already running first. "
                        "Only works for the backend/web.py + uvicorn convention unless you pass an explicit cmd.",
        "parameters": {"type": "object", "properties": {
            "project": {"type": "string", "description": "The clone's name (from redteam_clone_repo/redteam_clone_private_repo), or \"self\"."},
            "cmd": {"type": "string", "description": "Optional: an explicit shell command to start the app instead of the uvicorn default."},
        }, "required": ["project"]},
    },
    {
        "name": "sandbox_app_restart",
        "description": "Restarts the sandboxed app from the project's CURRENT working copy. Call this after writing a fix, right before "
                        "re-running pentest_zap, so the re-scan is against the fixed code.",
        "parameters": {"type": "object", "properties": {
            "project": {"type": "string"},
            "cmd": {"type": "string"},
        }, "required": ["project"]},
    },
    {
        "name": "sandbox_app_stop",
        "description": "Stops the sandboxed app. Call this once you are done pentesting it.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "sandbox_app_status",
        "description": "Whether a sandboxed app is running right now, which project, and its recent output.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "export_project",
        "description": "Zips a finished project folder from /REPL/work into aegis_out/ on the host -- the only way anything leaves the "
                        "sandbox. Only call this once every asked-for finding is confirmed gone by its own re-scan.",
        "parameters": {"type": "object", "properties": {"project": {"type": "string"}}, "required": ["project"]},
    },
    {
        "name": "create_word_document",
        "description": "Creates a real, downloadable .docx report. Call this once the work a request asked for is actually done (the scan, "
                        "or the scan + any fix) -- same as every real finding report, this is automatic, not conditional on the operator "
                        "asking for a file. body is light markdown: '# '/'## '/'### ' headings, '- ' or '1. ' bullets, plain paragraphs.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string", "description": "e.g. \"Static fix report -- self\"."},
            "body": {"type": "string", "description": "The report body: findings before/after, the real fix made for each, light markdown."},
        }, "required": ["title", "body"]},
    },
    {
        "name": "check_scanner_versions",
        "description": "Checks if security scanning tools (gitleaks, Bandit, Semgrep, pip-audit, Trivy, OWASP ZAP, npm) have updates available. "
                        "Call this ONCE during your initial greeting to show tool recency status. Returns current vs latest version for each tool.",
        "parameters": {"type": "object", "properties": {}},
    },
]

DISPATCH = {
    "redteam_clone_repo": redteam_tools.redteam_clone_repo,
    "redteam_clone_private_repo": redteam_tools.redteam_clone_private_repo,
    "redteam_gitleaks": redteam_tools.redteam_gitleaks,
    "redteam_bandit": redteam_tools.redteam_bandit,
    "redteam_semgrep": redteam_tools.redteam_semgrep,
    "redteam_pip_audit": redteam_tools.redteam_pip_audit,
    "redteam_npm_audit": redteam_tools.redteam_npm_audit,
    "redteam_trivy": redteam_tools.redteam_trivy,
    "pentest_zap": redteam_tools.pentest_zap,
    "pentest_lateral_movement": redteam_tools.pentest_lateral_movement,
    "check_scanner_versions": redteam_tools.check_scanner_versions,
    "pentestlive_consent": pentest_tools.pentestlive_consent,
    "pentestlive_scan": pentest_tools.pentestlive_scan,
    "verify_sandbox_safety": sandbox_verify.verify_sandbox_safety,
    "bash_run": sandbox_tools.bash_run,
    "edit_file": sandbox_tools.edit_file,
    "sandbox_app_start": sandbox_web_tools.sandbox_app_start,
    "sandbox_app_restart": sandbox_web_tools.sandbox_app_restart,
    "sandbox_app_stop": sandbox_web_tools.sandbox_app_stop,
    "sandbox_app_status": sandbox_web_tools.sandbox_app_status,
    "repl_run": sandbox_tools.repl_run,
    "repl_list": sandbox_tools.repl_list,
    "export_project": sandbox_tools.export_project,
    "create_word_document": doc_tools.create_word_document,
}
