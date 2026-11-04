<p align="center"><img src="docs/assets/aegis-shield-arrow.png" alt="Aegis shield deflecting an incoming arrow" width="220"></p>
<p align="center"><img src="docs/assets/aegis-hackathon-badge.jpg" alt="Meta Global AI Developer Hackathon — 10 days on Meta's newest AI models, $1M in cash prizes" width="520"></p>

<h1 align="center">**Aegis**</h1>

<p align="center"><b>The AI security agent that finds the weakness, fixes it, and proves the fix holds.</b><br>
<b>A</b>gentic <b>E</b>nterprise <b>G</b>uard for <b>I</b>nfo<b>S</b>ec — by <b>Musiac</b> (<b>Mus</b>e <b>I</b>ntelligence for <b>A</b>dvanced <b>C</b>yberSec), built for the <a href="https://dev.meta.ai/events/global-hackathon">Meta Global Hackathon</a></p>

<p align="center"><b>Watch the 3-minute demo of <b>Aegis</b>:</b> <a href="https://ideanirvana.sharepoint.com/:v:/g/IQAni_tht9iYQIzv13nULSSdAZrF2nXHbckMhlBxdKDw1IA?e=NyQUzi">demo video</a></p>

---

## Overview

In Greek mythology the **Aegis** was the divine shield that turned any enemy who looked at it to stone. This **Aegis** does not wait for an attack: it finds the vulnerability first, fixes it in place, and proves the fix holds.

Think of **Aegis** as a guard dog that is also a locksmith. It scans your code and container images, actively tests the locks on a target you point it at, fixes the weak ones itself, then checks the door again. It does not stop at a report: it loops scan → fix → re-scan until the scan comes back clean. It is powered entirely by Meta's **Muse Spark** and **Muse Wonder** models.

**Key capabilities**

- **Scan:** **gitleaks**, **Bandit**, **Semgrep**, **pip-audit**, **npm audit** and **Trivy**, on your code or any GitHub repo you name.
- **Attack:** a real OWASP ZAP pentest against a server **Aegis** stands up from the cloned repo.
- **Fix and prove it:** writes real fixes in an isolated sandbox, re-scans, and reports before and after.
- **Report:** a Word report and a zip of the fixed project.
- **Watch it work:** a live terminal pane shows every command it runs.
- **Safe by design:** the sandbox where fixes are written has no network, and active attacks need your explicit consent. See [Security](#security).

## Quick start

You need Docker (running), a bash shell (Linux, macOS, or WSL2), `rsync`, `python3`, `curl`, and a **Muse** API key.

**What your computer needs**
- **Disk:** at least **25 GB free**. **Aegis** uses about 12 GB once installed, and about 17 GB at the peak of the first install.
- **Memory:** at least **8 GB of RAM**, with **4 GB free**. **Aegis** itself peaked at about 2 GB in our tests; Docker needs the rest.
- **Processor:** at least a **quad-core** (4 cores). **Aegis** uses every core it can during a scan, so more cores finish sooner.
- **Internet:** the first install downloads roughly 3 GB.

<details>
<summary><b>New computer? How to install Docker (and WSL 2 on Windows)</b></summary>

**Mac**
1. Find your chip: Apple menu, then *About This Mac* (it says Apple silicon or Intel).
2. Download **Docker Desktop for Mac** from [docs.docker.com/desktop/setup/install/mac-install](https://docs.docker.com/desktop/setup/install/mac-install/), choosing the Apple silicon or Intel version.
3. Open the downloaded file, drag Docker into *Applications*, open it, and accept the terms.
4. Wait until Docker Desktop says it is running (a whale icon in the menu bar). Leave it running while you install **Aegis**.
5. On a brand-new Mac, the first `git` or `python3` command may offer to install the *command line developer tools*. Click *Install* and wait for it to finish.

**Windows** (**Aegis** runs inside WSL 2, a Linux that comes with Windows 10 version 2004 or later, and Windows 11)
1. Install WSL 2: open the Start menu, type *PowerShell*, right-click it, choose *Run as administrator*, and run `wsl --install`. Restart the computer when it asks. When Ubuntu opens, it asks you to create a username and password. Details: [learn.microsoft.com/windows/wsl/install](https://learn.microsoft.com/en-us/windows/wsl/install).
2. Download and run **Docker Desktop for Windows** from [docs.docker.com/desktop/setup/install/windows-install](https://docs.docker.com/desktop/setup/install/windows-install/). Keep the *WSL 2* option selected when the installer asks. If your PC has an Arm processor (for example a Snapdragon or NVIDIA RTX Spark laptop; *Settings*, *System*, *About* says "ARM-based processor"), choose the **Arm** download on that page; Docker marks it as Early Access.
3. Open Docker Desktop, accept the terms, and wait until it says it is running. Then open *Settings*, *Resources*, *WSL integration*, and switch it on for *Ubuntu*.
4. Open **Ubuntu** from the Start menu. This is the bash shell the steps below use. Run `sudo apt update && sudo apt install -y git rsync python3 curl` once, then do the install steps below inside Ubuntu, in your home folder.
5. Keep the Ubuntu window open, and keep the PC awake (plugged in, with sleep set to "never" while on power), until the install finishes. In our test, Windows shut Ubuntu down while no window was open, and sleep did the same; either one stops the install part-way. Running `bash install.sh` again is safe and carries on from the cached steps.

*What we tested:* a new Windows 11 PC with an Arm processor, Ubuntu in WSL 2, and Docker Engine installed inside Ubuntu (not Docker Desktop). We have not tested the Docker Desktop route above ourselves.

**Linux**: install Docker Engine from [docs.docker.com/engine/install](https://docs.docker.com/engine/install/).

Docker Desktop is free for personal use and small businesses; larger companies need a paid plan (see Docker's terms).
</details>

```bash
git clone https://github.com/Musiac/Aegis
cd Aegis
cp .env.example .env
```

Now open the file `.env` in the **Aegis** folder, find the line `MUSE_API_KEY=`, type your own Meta API key right after it, and save the file. Then run:

```bash
bash install.sh
```

This builds and starts everything. It can take 5 to 10 minutes on a fast connection (see the note below). If an "Allow" pop-up appears, click Allow.

How long the first install takes depends on your internet speed. On a new Windows laptop with a good connection it took **about 9 minutes 30 seconds** (the slowest steps were the scanner image at 4 minutes and the scanner tools and vulnerability databases at 3 minutes). The same laptop took **30 minutes**, and once stopped on a download time-out, when its Wi-Fi was losing a quarter of its packets; if your install is slow or a download times out, try a cable connection, or turn off the Wi-Fi card's power saving, then run `bash install.sh` again. On a Mac with a fast connection the last step took under a minute. Later installs take under a minute because everything is cached.

While it installs, a progress line with a spinner and a running clock shows that it has not hung. When it finishes, open Docker and you will see two new containers, `aegis-code` and `aegis-libraries`. (A short-lived sandbox of three more containers starts when **Aegis** needs it and is removed after 5 idle minutes.)

**Where the fixed code goes:** the zip of the fixed project (it also contains the Word report) is saved in the `aegis_out` folder inside the **Aegis** folder you installed from, and the chat tells you the full path. On Windows that folder is inside Ubuntu; in File Explorer, type `\\wsl$` in the address bar and open Ubuntu, `home`, your user name, `Aegis`, `aegis_out`.

Then open **http://127.0.0.1:8900** in your browser. A terminal opens in the left half of your screen and a chat window in the right half. The very first time only, **Aegis** spends a few minutes getting its scanner tools and their databases ready (the install does most of this for you). When the chat shows the version number of every scanner tool, it is ready: type your request in the chat box at the bottom right.

**Which model?** The page starts on **Muse Spark Contributor**, the least costly Meta model. Use it for public repositories only, never for private ones. **Muse Wonder** is Meta's most capable model but also the most costly, so for a medium or large repository choose Wonder from the drop-down at the top of the page.

Try one of these requests:

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

`<target>` is **Aegis**'s own source (`self`) or any public GitHub repo you point it at (private repos work with a token).

## Models

Every model **Aegis** calls at runtime is a Meta model:

- **`muse-spark-1.3`** drives every chat turn, tool decision and fix. On public repos **Aegis** automatically uses the cheaper contributor tier; on private repos and its own code it uses the standard tier, where your content is never used for training.
- **`muse-wonder-1.0`** is the bigger model, one click away in the model dropdown, for jobs where Spark struggles.
- **`muse-voice-transcribe-1.0`** turns push-to-talk speech into text.

Spoken replies use the browser's own built-in voice, which is an operating-system feature and not a model call. Details: [aegis_usage_details.md](aegis_usage_details.md#meta-models-vs-osbrowser-features-full).

## Results

We ran **Aegis** end to end on six real public repositories, from small to large. Five finished clean on the static scanners; the sixth had 3 findings the tool cannot fix, because that repository's own package pins conflict. Runs took about 1 to 20 minutes and cost $0.30 to $2.50.

On one repo with a very long findings list (`openai/openai-agents-python`), **Muse Spark** struggled and was stopped; its bigger brother **Muse Wonder** did the job.

In a head-to-head on the same repo, **Muse Spark** finished about 32% faster than our own self-hosted model. Every run, with times and costs: [test/test_results.md](test/test_results.md).

## Where we stand

We ran **Aegis** next to [Strix](https://github.com/usestrix/strix), the most-starred open-source AI pentesting tool on GitHub, on the same project, with the same AI model, on the same day. We ran it ourselves, so it is not an independent test. All the numbers and caveats are in [aegis_vs_strix.md](aegis_vs_strix.md).

| | **Aegis** | Strix |
|---|---|---|
| Has a user interface | ✅ | ✅ |
| Shows its work live | ✅ | ✅ |
| Can be stopped | ✅ | ✅ |
| Can pause/resume | ✅ | 🟡 Only at budget limit |
| Attacks a running app | ✅ | ✅ |
| Proves bugs with working exploits | ❌ | ✅ |
| Fixes the issues it finds | ✅ | 🟡 Cloud product only |
| Re-checks that its fix worked | ✅ | ❌ |
| Gives you the fixed project to download | ✅ | ❌ |
| Gives you a diff of every fix made | ✅ | ❌ |
| Gives you a full Word report to download | ✅ | ❌ |
| Gives you the full terminal log to download | ✅ | ❌ |
| You can talk to it by voice | ✅ | ❌ |
| Keeps its own scanners up to date | ✅ | ❌ |
| Switch the AI model from the screen | ✅ | ❌ |
| Asks consent before probing a live site | ✅ | ❌ |
| Attacks a live website | 🟡 Probe only | ✅ |
| Depth modes, pull-request-only scans | ❌ | ✅ |
| Clones private repos from a token file | ✅ | 🟡 Uses your own git login |
| Works in CI/CD such as GitHub Actions | ❌ | ✅ |

On the same project, an **Aegis** run took 7 to 12 minutes and cost $1.11 to $2.47, and it fixed what it found. A Strix run took **20 to 31 minutes** and cost **$21 to $29**, and it reported what it found, including logic bugs that **Aegis**'s scanners missed. The two tools do different jobs, so this is not a ranking.

If you like **Aegis**, a star on this repository is appreciated.

## Security

**Aegis** attacks other people's code, so we treated its own security as a feature:

- **We ran Aegis on itself.** It scans and fixes its own source, and the Strix pentester found 4 real bugs in it that static scanners miss. We fixed every one.
- **We tried to break out of the sandbox ourselves** with six real attacks. Five were blocked or contained; the sixth found a real bug in our export step, now fixed.
- **The sandbox is locked down:** the sandbox where code is read and fixed has no network, a read-only root, a non-root user and capped resources, and real credentials never enter it. The separate container that runs the target app for a pentest can reach the internet, but only so it can install that app's dependencies.
- **Active attacks need consent,** and private code automatically uses the non-training model tier.
- **Aegis keeps its own scanners up to date,** and structural guards stop the agent from calling a fix done when it isn't.

Full record of the attacks and results: [aegis_security_details.md](aegis_security_details.md).

## Architecture

**Aegis** runs as two permanent containers and a short-lived sandbox:

- **`aegis-code`** holds the **Aegis** main code: the chat loop and the web UI.
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
| [aegis_vs_strix.md](aegis_vs_strix.md) | **Aegis** and Strix side by side, with every number |
| [aegis_background.md](aegis_background.md) | The Musiacs story and how **Aegis** relates to our other product |

## Built for the hackathon

We're **Musiacs** — **Muse Maniacs** — at **IdeaNirvana**. **Aegis** is a new, separate project, in its own repository created on 27 October 2026, submitted by the sole founder and developer in the Startup track. **Aegis**'s pattern and architecture were ported from Jiina, our closed-source single-agent product, whose skills cover other areas such as ERP, DB Intel and document understanding. The code for **Aegis** follows the same single-agent pattern and architecture, but we wrote **Aegis** for cybersecurity work, with the pentest, redteam, fixpentest and fixredteam skills, for this hackathon, which started on 26 October 2026. Jiina's code and history are not in this repository. The full story, including the six findings **Muse** reported on our live site before the hackathon, is in [aegis_background.md](aegis_background.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Musiac/IdeaNirvana.
