<p align="center"><img src="docs/assets/aegis-shield-arrow.png" alt="Aegis shield deflecting an incoming arrow" width="220"></p>
<p align="center"><img src="docs/assets/aegis-hackathon-badge.jpg" alt="Meta Global AI Developer Hackathon — 10 days on Meta's newest AI models, $1M in cash prizes" width="520"></p>

<h1 align="center">Aegis</h1>

<p align="center"><b>The AI security agent that finds the weakness, fixes it, and proves the fix holds.</b><br>
<b>A</b>gentic <b>E</b>nterprise <b>G</b>uard for <b>I</b>nfo<b>S</b>ec — by <b>Musiac</b> (<b>Mus</b>e <b>I</b>ntelligence for <b>A</b>dvanced <b>C</b>yberSec), built for the <a href="https://dev.meta.ai/events/global-hackathon">Meta Global Hackathon</a></p>

---

## Overview

In Greek mythology the aegis was the divine shield that turned any enemy who looked at it to stone. This Aegis does not wait for an attack: it finds the vulnerability first, fixes it in place, and proves the fix holds.

Think of Aegis as a guard dog that is also a locksmith. It scans your code and container images, actively tests the locks on a target you point it at, fixes the weak ones itself, then checks the door again. It does not stop at a report: it loops scan → fix → re-scan until the scan comes back clean. It is powered entirely by Meta's **Muse Spark** and **Muse Wonder** models.

**Key capabilities**

- **Scan:** gitleaks, Bandit, Semgrep, pip-audit, npm audit and Trivy, on your code or any GitHub repo you name.
- **Attack:** a real OWASP ZAP pentest against a server Aegis stands up from the cloned repo.
- **Fix and prove it:** writes real fixes in an isolated sandbox, re-scans, and reports before and after.
- **Report:** a Word report and a zip of the fixed project.
- **Watch it work:** a live terminal pane shows every command it runs.
- **Safe by design:** the sandbox has no network, and active attacks need your explicit consent. See [Security](#security).

## Quick start

You need Docker, a bash shell (Linux, macOS, or WSL2), `rsync`, `python3`, and a **Muse** API key.

```bash
git clone https://github.com/Musiac/Aegis
cd Aegis
cp .env.example .env     # put your MUSE_API_KEY in it
bash install.sh          # builds and starts everything
```

Then open **http://127.0.0.1:8900** and type a request. Try one of these:

- `scan https://github.com/usestrix/strix and report what you find, but do not fix anything.`
- `scan self and fix any issue you find.`
- `go to the public repo https://github.com/usestrix/strix, load it locally, stand up its server if it has one, run the tests, and fix the issues found.`

More install options, the CLI, and a dozen more example prompts: [aegis_usage_details.md](aegis_usage_details.md).

## What it does

| Command | What happens |
|---|---|
| `redteam <target>` | Static scan only. Reports every finding and asks before fixing anything. |
| `redteam <target> and fix it` | Scans, fixes in a sandbox copy, re-scans to confirm each fix, reports before and after. |
| `pentest <target>` | Active OWASP ZAP scan against a target you have stood up, or one live probe of a URL you explicitly consent to (typed `PENTESTLIVE`). |
| `pentest <target> and fix it` | Attacks, writes a real fix, re-attacks to prove it is closed. |

`<target>` is Aegis's own source (`self`) or any public GitHub repo you point it at (private repos work with a token).

## Models

Every model Aegis calls at runtime is a Meta model:

- **`muse-spark-1.3`** drives every chat turn, tool decision and fix. On public repos Aegis automatically uses the cheaper contributor tier; on private repos and its own code it uses the standard tier, where your content is never used for training.
- **`muse-wonder-1.0`** is the bigger model, one click away in the model dropdown, for jobs where Spark struggles.
- **`muse-voice-transcribe-1.0`** turns push-to-talk speech into text.

Spoken replies use the browser's own built-in voice, which is an operating-system feature and not a model call. Details: [aegis_usage_details.md](aegis_usage_details.md#meta-models-vs-osbrowser-features-full).

## Results

We ran Aegis end to end on six real public repositories, from small to large. Five finished clean on the static scanners; the sixth had 3 findings the tool cannot fix, because that repository's own package pins conflict. Runs took about 1 to 20 minutes and cost $0.30 to $2.50.

On one repo with a very long findings list (`openai/openai-agents-python`), **Muse Spark** struggled and was stopped; its bigger brother **Muse Wonder** did the job.

In a head-to-head on the same repo, **Muse Spark** finished about 32% faster than our own self-hosted model. Every run, with times and costs: [test/test_results.md](test/test_results.md).

## Security

Aegis attacks other people's code, so we treated its own security as a feature:

- **We ran Aegis on itself.** It scans and fixes its own source, and the Strix pentester found 4 real bugs in it that static scanners miss. We fixed every one.
- **We tried to break out of the sandbox ourselves** with six real attacks. Five were blocked or contained; the sixth found a real bug in our export step, now fixed.
- **The sandbox is locked down:** no network, read-only root, non-root user, capped resources. Real credentials never enter it.
- **Active attacks need consent,** and private code automatically uses the non-training model tier.
- **Aegis keeps its own scanners up to date,** and structural guards stop the agent from calling a fix done when it isn't.

Full record of the attacks and results: [aegis_security_details.md](aegis_security_details.md).

## Architecture

Aegis runs as two permanent containers and a short-lived sandbox:

- **`aegis-code`** holds the Aegis main code: the chat loop and the web UI.
- **`aegis-libraries`** holds the heavy scanner tools.
- **A sandbox trio** is created on demand for fixes and pentests, and removed after 5 idle minutes.

The code and the libraries are separate so that a code change rebuilds only the small image, which keeps builds and deploys fast. The diagrams, the container details and the LightMA agent framework are in [aegis_architecture.md](aegis_architecture.md).

## More documentation

| | |
|---|---|
| [aegis_usage_details.md](aegis_usage_details.md) | Full install, CLI, UI, logs, example prompts, status |
| [aegis_architecture.md](aegis_architecture.md) | Diagrams, containers, the LightMA framework |
| [container_details.md](container_details.md) | Every container, network and volume |
| [aegis_security_details.md](aegis_security_details.md) | The six sandbox attacks and results |
| [aegis_guardrails_and_nudges.txt](aegis_guardrails_and_nudges.txt) | The guardrails that keep a task on track |
| [test/test_results.md](test/test_results.md) | Test runs and the model benchmark |
| [aegis_background.md](aegis_background.md) | The Musiacs story and how Aegis relates to our other product |

## Built for the hackathon

We're **Musiacs** — **Muse Maniacs** — at **IdeaNirvana**. Aegis is a new, separate project, in its own repository created on 27 October 2026, submitted by the sole founder and developer in the Startup track. It reuses patterns we first developed in our closed-source product, Jiina; Jiina's code and history are not in this repository. The full story, including the six findings **Muse** reported on our live site before the hackathon, is in [aegis_background.md](aegis_background.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Musiac/IdeaNirvana.
