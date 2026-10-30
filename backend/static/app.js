(() => {
  const term = document.getElementById("terminal");
  const chat = document.getElementById("chat");
  const status = document.getElementById("status");
  const providerSelect = document.getElementById("provider");
  const totalCost = document.getElementById("total-cost");
  const form = document.getElementById("composer");
  const input = document.getElementById("input");
  const sendBtn = document.getElementById("send");
  const DEFAULT_PLACEHOLDER = input.placeholder;
  const taskDots = document.getElementById("task-dots");
  const downloadTerminalBtn = document.getElementById("download-terminal");
  const micBtn = document.getElementById("mic-btn");
  const voiceToggle = document.getElementById("voice-toggle");
  const voiceTtsLabel = document.getElementById("voice-tts-label");
  const voiceAsrLabel = document.getElementById("voice-asr-label");
  const muteSpeakerToggle = document.getElementById("mute-speaker-toggle");
  const warningBanner = document.getElementById("warning-banner");

  let ws = null;
  let isBusy = false;
  let chatSid = null;   // the chat session's own id, sent by the server right after connect -- see web.py's "sid" message;
                         // passed to /ws/asr so its real per-call cost lands in THIS session's total (TTS is browser-side, no cost)
  let museConfigured = false;   // MUSE_API_KEY actually set on the host -- gates both Send and the mic (ASR is Muse too)
  let voiceOn = false;          // Voice toggle state -- gates TTS + mic together (mic starts OFF until this is ON)
  // Mute Speaker: browser TTS plays out of the Mac's real speakers, and the mic (also real hardware, no echo
  // cancellation between the two) picks that audio right back up and corrupts the ASR transcript -- Gemini TTS
  // never had this problem (narrower/quieter voice, different timing), browser TTS does. Mute before recording,
  // unmute after -- speakOne() below checks this flag and skips playback entirely while muted (never queues it for
  // later; a muted message is simply not spoken).
  let speakerMuted = false;
  // TTS backend for the Voice toggle's spoken replies: always "browser" (the OS/browser's own Web Speech API --
  // not an AI model call at all). A local-Kokoro path was built 2026-10-29 then explicitly reverted/disabled the
  // same day after Meta's hackathon organizers ruled it out: "Every model your project calls at runtime must be
  // a Meta model, so a third-party TTS model like Kokoro-82M can't be used even if it runs locally on your own
  // CPU... a built-in system or browser voice that isn't an AI model call is fine." The backend endpoint and
  // container still exist (kokoro/, /api/tts_kokoro) for personal non-submission use, but nothing in this file
  // calls them, and install.sh no longer starts the container by default -- see README's "Meta models vs.
  // OS/browser features" section.
  const ttsBackend = "browser";

  function showWarning(text, isError) {
    warningBanner.textContent = text;
    warningBanner.className = "warning-banner" + (isError ? " error" : "");
    warningBanner.hidden = false;
  }
  function clearWarning() {
    warningBanner.hidden = true;
  }

  function updateMicEnabled() {
    micBtn.disabled = !(voiceOn && museConfigured);
  }

  // Page-load checks, run once: (1) is MUSE_API_KEY even set -- loadProviders() below already needs /api/providers for
  // the dropdown, so this piggybacks on that; (2) if it IS set, a real ping so a configured-but-broken key (no
  // balance, revoked) surfaces here instead of on the first chat turn.
  async function checkMuseStatus() {
    try {
      const r = await fetch("/api/providers");
      const d = await r.json();
      museConfigured = !!(d.providers && d.providers.includes("muse"));
    } catch {
      museConfigured = false;
    }
    if (!museConfigured) {
      showWarning("MUSE_API_KEY is not set. Aegis will show a startup greeting and scanner version check, then stop -- Send stays disabled until a key is configured.");
      sendBtn.disabled = true;
      updateMicEnabled();
      return;
    }
    try {
      const r = await fetch("/api/muse_ping");
      const d = await r.json();
      if (!d.ok) {
        showWarning(`MUSE_API_KEY is set but not working: ${d.error || "unknown error"}`, true);
      }
    } catch (e) {
      showWarning(`Could not verify MUSE_API_KEY: ${e}`, true);
    }
    updateMicEnabled();
  }

  voiceToggle.addEventListener("click", async () => {
    if (voiceOn) {
      voiceOn = false;
      voiceToggle.textContent = "Voice: OFF";
      voiceToggle.setAttribute("aria-pressed", "false");
      voiceTtsLabel.hidden = true;
      voiceAsrLabel.hidden = true;
      muteSpeakerToggle.hidden = true;
      if (recording) stopRecording();
      window.speechSynthesis.cancel();
      stopKokoroAudio();
      speechQueue.length = 0;   // stop any in-progress catch-up replay; does not resume where it left off next time -- see below
      updateMicEnabled();
      return;
    }
    voiceToggle.disabled = true;
    try {
      clearWarning();
      voiceOn = true;
      voiceToggle.textContent = "Voice: ON";
      voiceToggle.setAttribute("aria-pressed", "true");
      voiceTtsLabel.textContent = "TTS: browser (OS/browser voice, not a model call)";
      voiceTtsLabel.hidden = false;
      voiceAsrLabel.textContent = "ASR: muse";
      voiceAsrLabel.hidden = false;
      muteSpeakerToggle.hidden = false;
      updateMicEnabled();
      // Replay ONLY the first MANDATORY_REPLAY_COUNT assistant messages (the billing disclosure + the scanner-check
      // announcement) every time Voice is turned on, no matter how late -- never the rest of whatever's already on
      // screen (a real report: turning Voice on even a few seconds late had it reading through the ENTIRE sandbox
      // verification paragraph that had already finished appearing, several screens behind live). Anything beyond
      // those first two is intentionally skipped here; live playback resumes normally for whatever message arrives
      // NEXT after this toggle, via the ordinary speak() path below -- never for backlog already on screen.
      speechQueue.length = 0;
      speechQueue.push(...assistantHistory.slice(0, MANDATORY_REPLAY_COUNT));
      processSpeechQueue();
    } finally {
      voiceToggle.disabled = false;
    }
  });

  // Mute before switching the mic on, unmute after switching it off and before submitting the transcribed text --
  // cancels anything mid-playback immediately so a muted recording never catches the tail end of a sentence.
  muteSpeakerToggle.addEventListener("click", () => {
    speakerMuted = !speakerMuted;
    muteSpeakerToggle.textContent = speakerMuted ? "Speaker: MUTED" : "Speaker: ON";
    muteSpeakerToggle.setAttribute("aria-pressed", String(speakerMuted));
    if (speakerMuted) { window.speechSynthesis.cancel(); stopKokoroAudio(); }
  });

  // Classifies each line the same way main Jiina's own terminal view distinguishes a tool call from its result
  // (see Jiina/frontend/nextjs -- terminal-cmd/-out/-progress): web.py emits "-> name(args)" for a call,
  // "   <result>" (3-space indent) for its result, and "[name] text" for progress/status lines.
  function addTerminalLine(text) {
    const div = document.createElement("div");
    let cls = "line";
    if (/^->\s/.test(text)) cls = "line cmd";
    else if (/^\s{3}/.test(text)) cls = "line out";
    else if (/^\[/.test(text)) cls = "line progress";
    div.className = cls;
    div.textContent = text;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
  }

  function addChatMsg(role, text) {
    const div = document.createElement("div");
    div.className = `msg ${role}`;
    if (role === "assistant" && window.cjMarkdown) {
      // Aegis answers in Markdown (bold, tables, bullets, code): render it. The renderer HTML-escapes everything first, so scan
      // output or page text inside a reply cannot inject markup. The user's own messages and errors stay plain text.
      div.innerHTML = '<span class="who">Aegis</span><div class="md">' + window.cjMarkdown.render(text) + "</div>";
    } else {
      div.textContent = (role === "user" ? "> " : role === "assistant" ? "Aegis: " : "") + text;
    }
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  }

  // The "she is working, not hung" indicator, placed exactly where the owner asked: inline right next to
  // "Aegis" in the live turn, same as the full-featured version's .turn-dots (not the composer/Send-button area --
  // that was the wrong spot on the first attempt). Shown the instant a turn starts; removed the moment any
  // real content for that turn arrives (chat text or a document card), or on "done" if nothing ever came.
  let pendingTurn = null;
  function showPendingDots() {
    const div = document.createElement("div");
    div.className = "msg assistant pending";
    div.innerHTML = 'Aegis <span class="turn-dots busy" aria-hidden="true"><span></span><span></span><span></span></span>';
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
    pendingTurn = div;
  }
  function clearPendingDots() {
    if (pendingTurn) {
      pendingTurn.remove();
      pendingTurn = null;
    }
  }

  // The owner asked for the exact "download the whole run" idiom the full-featured version's page offers for her terminal
  // view -- pure client-side (Blob + a throwaway anchor click), no server round trip.
  function downloadTerminalLog() {
    const lines = Array.from(term.querySelectorAll(".line")).map((d) => d.textContent);
    if (lines.length === 0) return;
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-terminal-${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // create_word_document's real file, delivered as its own WebSocket message (see web.py's emit_document) --
  // decoded into a Blob and shown as a download card in the chat pane, same end-user shape as the full-featured version's
  // WORD-badge download cards (Blob URLs here live only as long as the tab is open, same as hers).
  function addDocumentCard(doc) {
    try {
      const bytes = Uint8Array.from(atob(doc.data_base64), (c) => c.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes], { type: doc.mime || "application/octet-stream" }));
      const card = document.createElement("div");
      card.className = "doc-card";
      const badge = document.createElement("span");
      badge.className = "doc-badge";
      badge.textContent = "WORD";
      const name = document.createElement("span");
      name.className = "doc-name";
      name.textContent = doc.filename;
      const meta = document.createElement("span");
      meta.className = "doc-meta";
      meta.textContent = `${Math.max(1, Math.round((doc.size || bytes.length) / 1024))} KB`;
      const a = document.createElement("a");
      a.href = url;
      a.download = doc.filename;
      a.textContent = "Download";
      card.append(badge, name, meta, a);
      chat.appendChild(card);
      chat.scrollTop = chat.scrollHeight;
    } catch (e) {
      addTerminalLine(`[ui] could not decode the document: ${e}`);
    }
  }

  function setBusy(busy) {
    // Typing stays open while she works, same as before -- but Send/Enter now stays enabled too (2026-10-29): a
    // message sent while busy is read by the server as a possible "stop"/"pause" interrupt (see web.py's
    // ws_endpoint), so disabling Send here would make those words impossible to actually deliver mid-task. The
    // submit handler below still shows the normal pending-dots UI only when nothing was already in flight.
    // Send/input get an unmistakably different LOOK while busy instead (2026-10-30, real operator confusion
    // otherwise): an unchanged "Send" button made someone assume a quick reply meant the whole task was done,
    // type a brand new unrelated request, and get an unexpected "still working" rejection back.
    isBusy = busy;
    sendBtn.disabled = !museConfigured;
    sendBtn.textContent = busy ? "Working…" : "Send";
    sendBtn.classList.toggle("busy", busy);
    input.classList.toggle("busy", busy);
    input.placeholder = busy ? 'Aegis is working -- type "pause" or "stop" to interrupt' : DEFAULT_PLACEHOLDER;
    // Dots in two places at once, per the owner: a pill next to Send (at-a-glance, before even looking at the
    // chat pane) AND inline next to "Aegis" in the chat turn (showPendingDots/clearPendingDots below).
    taskDots.style.display = busy ? "inline-flex" : "none";
    if (busy) {
      showPendingDots();
    } else {
      clearPendingDots();   // a turn that ended with no chat text/document at all (e.g. only tool calls, no final answer)
    }
  }

  async function loadProviders() {
    try {
      const r = await fetch("/api/providers");
      const d = await r.json();
      providerSelect.innerHTML = "";
      if (!d.providers || d.providers.length === 0) {
        const opt = document.createElement("option");
        opt.textContent = "none configured";
        providerSelect.appendChild(opt);
        providerSelect.disabled = true;
        return;
      }
      if (d.auto_route) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = `auto (scan: ${d.auto_route.scan} / fix: ${d.auto_route.fix})`;
        providerSelect.appendChild(opt);
      }
      for (const p of d.providers) {
        const opt = document.createElement("option");
        opt.value = p;
        opt.textContent = p;
        providerSelect.appendChild(opt);
      }
    } catch (e) {
      addTerminalLine(`[ui] could not load providers: ${e}`);
    }
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.onopen = () => {
      status.textContent = "connected";
      setBusy(true);  // Automatic greeting is coming, show spinner immediately
    };
    ws.onclose = () => { status.textContent = "disconnected -- reload to reconnect"; setBusy(true); };
    ws.onerror = () => { status.textContent = "connection error"; };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch { return; }
      if (msg.type === "sid") {
        chatSid = msg.sid;
      } else if (msg.type === "chat") {
        clearPendingDots();
        addChatMsg("assistant", msg.text);
        speak(msg.text);
      } else if (msg.type === "status") {
        // A transient "Now doing X..." line next to the working dots, replacing the previous one; empty text clears it.
        if (msg.text) {
          if (!pendingTurn) showPendingDots();
          let label = pendingTurn.querySelector(".status-text");
          if (!label) { label = document.createElement("span"); label.className = "status-text"; pendingTurn.appendChild(label); }
          label.textContent = msg.text;
          chat.scrollTop = chat.scrollHeight;
        } else if (pendingTurn) {
          const label = pendingTurn.querySelector(".status-text");
          if (label) label.remove();
        }
      } else if (msg.type === "terminal") {
        addTerminalLine(msg.line);
      } else if (msg.type === "document") {
        clearPendingDots();
        addDocumentCard(msg);
      } else if (msg.type === "error") {
        clearPendingDots();
        addChatMsg("error", msg.text);
      } else if (msg.type === "cost") {
        // The FINAL value for this turn -- the server only ever sends this once run_turn has fully finished
        // accumulating every LLM round's real token cost, right before "done", so this always replaces the
        // display with the up-to-date running total for the whole session (never a partial mid-turn figure).
        totalCost.textContent = `Grand Total Cost: $${Number(msg.total_usd || 0).toFixed(3)}`;
      } else if (msg.type === "done") {
        setBusy(false);
        input.focus();
      }
    };
  }

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = input.value.trim();
    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    addChatMsg("user", text);
    // While a turn is already running, this message's own words decide what happens server-side (stop/pause
    // interrupt the running turn; anything else is rejected with an explanatory error) -- so a brand new pending
    // "Aegis is thinking" placeholder is only shown when nothing was already in flight. The busy pill/dots stay
    // up either way since the ORIGINAL task is still genuinely running.
    if (!isBusy) setBusy(true);
    // The dropdown is read on EVERY message, so changing it mid-session takes effect on the next task.
    const payload = { type: "user_message", text, provider: providerSelect.value || "" };
    ws.send(JSON.stringify(payload));
    input.value = "";
  });

  downloadTerminalBtn.addEventListener("click", downloadTerminalLog);

  // Example questions: page 1 = items 1-6, page 2 = items 7-12. Shown shortened; clicking one puts the FULL
  // text in the chat box (not sent) so it can be edited first. They cover everything she can do: static scan,
  // scan + fix, secrets, dependency CVEs, private repos, Word reports, active ZAP pentest, pentest + fix,
  // the cautious third-party liveness probe (PENTESTLIVE), and the scanner-version check.
  const EXAMPLES = [
    "go to the public repo https://github.com/usestrix/strix, load it locally and run static and if it has a server like gradio or fastapi then stand up the server and run dynamic tests, and fix the issues found in these tests.",
    "scan https://github.com/usestrix/strix and report what you find, but do not fix anything.",
    "scan self and fix any issue you find.",
    "check the dependencies of https://github.com/usestrix/strix for known CVEs (pip-audit and npm audit).",
    "look for hardcoded secrets and leaked API keys in https://github.com/usestrix/strix.",
    "check the versions of all your scanner tools and tell me which ones need an update.",
    "scan the private repo https://github.com/OWNER/REPO (my token is in /dynamic_pristine_rw/github_token.txt) and fix any issue you find.",
    "scan self with every scanner, fix everything you can, and give me a Word report of what you changed.",
    "go to the private repo https://github.com/OWNER/REPO (token file: /dynamic_pristine_rw/github_token.txt), load it locally and run redteam and if it has a server like gradio or fastapi then stand up the server and run pentest tests, and fix the issues found in these tests.",
    "pentest http://localhost:8080/ with ZAP, and if you get in, fix the vulnerability and prove it is closed.",
    "do a liveness and technology check on https://example.com (a site I do not own; I will type PENTESTLIVE to confirm).",
    "scan self with Bandit and Semgrep only, then explain each finding in plain language.",
  ];
  const SHORT_LEN = 42;
  const exampleList = document.getElementById("example-list");
  const exampleNav = document.getElementById("example-nav");
  let examplePage = 0;
  function renderExamples() {
    exampleList.innerHTML = "";
    EXAMPLES.slice(examplePage * 6, examplePage * 6 + 6).forEach((full) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "example-item";
      b.textContent = full.length > SHORT_LEN ? full.slice(0, SHORT_LEN).trimEnd() + "..." : full;
      b.title = full;
      b.addEventListener("click", () => {
        input.value = full;
        input.focus();
        input.setSelectionRange(full.length, full.length);
      });
      exampleList.appendChild(b);
    });
    exampleNav.innerHTML = examplePage === 0 ? "&rarr;" : "&larr;";
    exampleNav.title = examplePage === 0 ? "More example questions (7-12)" : "Back to example questions 1-6";
    exampleNav.setAttribute("aria-label", exampleNav.title);
  }
  exampleNav.addEventListener("click", () => { examplePage = examplePage === 0 ? 1 : 0; renderExamples(); });
  renderExamples();

  // Browser-native speech (window.speechSynthesis): only when Voice is toggled ON. Every assistant message is
  // recorded here, spoken or not, so that turning Voice ON always replays the first MANDATORY_REPLAY_COUNT messages
  // (the billing disclosure + the scanner-check announcement) in full, no matter how late Voice is turned on -- but
  // NEVER any backlog beyond those two: a real report found turning Voice on even a few seconds late had it reading
  // through an entire already-finished paragraph (the sandbox verification summary) that had long since scrolled
  // past live. Past the mandatory two, playback picks up with whatever message arrives NEXT after the toggle, never
  // anything already sitting on screen at toggle time. Queued, not pause-and-interrupt, so the two mandatory
  // messages play fully in order instead of the second cutting the first one off.
  const MANDATORY_REPLAY_COUNT = 2;
  const assistantHistory = [];
  const speechQueue = [];
  let speaking = false;

  // Chrome/Safari bug, confirmed here 2026-10-28: speechSynthesis silently stops firing onend on a long
  // utterance (the first real sentence, the account-notice greeting, was long enough to trigger it every time)
  // and the queue hangs forever waiting on an event that will never come. Splitting into short, sentence-sized
  // utterances sidesteps the bug almost entirely (it's a long-utterance issue), and each short chunk gets its own
  // SHORT bounded timeout, so even a genuine hang on one chunk costs a couple seconds, not minutes.
  function splitIntoSpeechChunks(text) {
    const sentences = text.match(/[^.!?]+[.!?]+(\s+|$)|[^.!?]+$/g) || [text];
    return sentences.map((s) => s.trim()).filter(Boolean);
  }

  function speakChunk(chunk) {
    return new Promise((resolve) => {
      const utter = new SpeechSynthesisUtterance(chunk);
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        clearTimeout(stuckTimer);
        resolve();
      };
      utter.onend = finish;
      utter.onerror = finish;
      const stuckTimer = setTimeout(finish, Math.max(4000, chunk.length * 110));
      window.speechSynthesis.speak(utter);
    });
  }

  // No-op kept only so the voiceToggle/muteSpeakerToggle handlers above don't need their own edits -- there is
  // no non-browser audio element to stop anymore (reverted 2026-10-29, see ttsBackend's own comment above).
  function stopKokoroAudio() {}

  async function speakOne(text) {
    const clean = (text || "").trim();
    if (!clean) return;
    if (speakerMuted) return;   // Mute Speaker is ON -- drop this message, never queue it for after unmute
    if (!("speechSynthesis" in window)) {
      addTerminalLine("[tts] browser speech synthesis not available");
      return;
    }
    for (const chunk of splitIntoSpeechChunks(clean)) {
      if (speakerMuted) return;   // muted mid-message -- stop immediately, don't speak the remaining chunks
      await speakChunk(chunk);
    }
  }

  async function processSpeechQueue() {
    if (speaking) return;
    speaking = true;
    while (speechQueue.length && voiceOn) {
      await speakOne(speechQueue.shift());
    }
    speaking = false;
  }

  function enqueueSpeech(text) {
    if (!voiceOn) return;
    speechQueue.push(text);
    processSpeechQueue();
  }

  function speak(text) {
    assistantHistory.push(text);
    enqueueSpeech(text);
  }

  // Push-to-talk mic: hold #mic-btn, speak, release -- captured audio is downsampled to mono PCM16 @ 24kHz (what
  // muse-voice-transcribe-1.0 expects, see web.py's /ws/asr) and streamed to the server over its own WebSocket as it's
  // captured, so the transcript is ready moments after release rather than waiting for a full upload+decode round trip.
  let micStream = null, audioCtx = null, micSource = null, micProcessor = null, asrWs = null, recording = false;

  function downsampleTo24k(input, inputRate) {
    if (inputRate === 24000) return input;
    const ratio = inputRate / 24000;
    const outLen = Math.round(input.length / ratio);
    const out = new Float32Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = input[Math.min(input.length - 1, Math.round(i * ratio))];
    return out;
  }
  function floatToPCM16(float32) {
    const buf = new ArrayBuffer(float32.length * 2);
    const view = new DataView(buf);
    for (let i = 0; i < float32.length; i++) {
      const s = Math.max(-1, Math.min(1, float32[i]));
      view.setInt16(i * 2, s < 0 ? s * 0x8000 : s * 0x7fff, true);
    }
    return buf;
  }

  async function startRecording() {
    if (recording) return;
    recording = true;
    micBtn.classList.add("recording");
    try {
      micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (e) {
      addTerminalLine(`[mic] permission denied or unavailable: ${e}`);
      recording = false;
      micBtn.classList.remove("recording");
      return;
    }
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const sidParam = chatSid ? `?sid=${encodeURIComponent(chatSid)}` : "";
    asrWs = new WebSocket(`${proto}//${location.host}/ws/asr${sidParam}`);
    asrWs.onmessage = (ev) => {
      let evt;
      try { evt = JSON.parse(ev.data); } catch { return; }
      if (evt.type === "partial" || evt.type === "final") {
        input.value = evt.text || "";
        if (evt.type === "final") input.focus();
      } else if (evt.type === "error") {
        addTerminalLine(`[mic] ${evt.text}`);
      } else if (evt.type === "cost_delta") {
        // Push-to-talk's own cost (muse-voice-transcribe-1.0, billed separately from the chat LLM calls) -- added
        // immediately so the pill doesn't look stale between chat turns; the next "cost" message from the main
        // chat socket replaces this with the authoritative total anyway.
        const current = parseFloat((totalCost.textContent.match(/[\d.]+/) || ["0"])[0]) || 0;
        totalCost.textContent = `Grand Total Cost: $${(current + (evt.usd || 0)).toFixed(3)}`;
      }
    };
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    micSource = audioCtx.createMediaStreamSource(micStream);
    micProcessor = audioCtx.createScriptProcessor(4096, 1, 1);
    micProcessor.onaudioprocess = (ev) => {
      if (!recording || !asrWs || asrWs.readyState !== WebSocket.OPEN) return;
      const down = downsampleTo24k(ev.inputBuffer.getChannelData(0), audioCtx.sampleRate);
      asrWs.send(floatToPCM16(down));
    };
    micSource.connect(micProcessor);
    micProcessor.connect(audioCtx.destination);
  }

  function stopRecording() {
    if (!recording) return;
    recording = false;
    micBtn.classList.remove("recording");
    if (asrWs && asrWs.readyState === WebSocket.OPEN) asrWs.send(new ArrayBuffer(0));  // end-of-utterance signal
    if (micProcessor) { micProcessor.disconnect(); micProcessor = null; }
    if (micSource) { micSource.disconnect(); micSource = null; }
    if (audioCtx) { audioCtx.close(); audioCtx = null; }
    if (micStream) { micStream.getTracks().forEach((t) => t.stop()); micStream = null; }
    setTimeout(() => { if (asrWs) { asrWs.close(); asrWs = null; } }, 2000);  // give the final transcript time to arrive
  }

  // Toggle, not hold: a true press-and-hold turned out unreliable in practice (the mic permission prompt itself can
  // steal the mouse/trigger a mouseleave the instant recording starts, stopping it again before the prompt is even
  // answered). Click once to start (button turns red/pulses), click again -- or anywhere else on the page -- to stop.
  micBtn.addEventListener("click", (ev) => {
    ev.preventDefault();
    if (recording) stopRecording(); else startRecording();
  });

  loadProviders();
  checkMuseStatus();
  connect();
})();
