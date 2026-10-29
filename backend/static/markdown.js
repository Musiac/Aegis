/* Small, dependency-free Markdown -> HTML for Aegis's chat pane: headings, bold/italic, inline code, fenced code, bullet and numbered lists
   (nested by indent), tables, blockquotes, horizontal rules and links. Every piece of text is HTML-escaped BEFORE any markup is applied, and links are
   limited to http(s), so text that came from a scan result or a target page can never inject HTML or script. Pure string in, string out. */
(function (root) {
  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function inline(raw) {
    const codes = [];
    let s = String(raw).replace(/`([^`\n]+)`/g, (m, c) => {
      codes.push("<code>" + esc(c) + "</code>");
      return "\u0000" + (codes.length - 1) + "\u0000";
    });
    s = esc(s);
    s = s.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, (m, t, u) => `<a href="${u}" target="_blank" rel="noopener noreferrer">${t}</a>`);
    s = s.replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g, (m, pre, u) => {
      const tail = (u.match(/[.,;:!?]+$/) || [""])[0];
      const url = tail ? u.slice(0, -tail.length) : u;
      return `${pre}<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>${tail}`;
    });
    s = s.replace(/\*\*(?=\S)([\s\S]+?)(?<=\S)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/__(?=\S)([\s\S]+?)(?<=\S)__/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*\w])\*(?=[^\s*])([^*\n]+?)(?<=[^\s*])\*(?![*\w])/g, "$1<em>$2</em>");
    s = s.replace(/(^|[^\w])_(?=[^\s_])([^_\n]+?)(?<=[^\s_])_(?![\w])/g, "$1<em>$2</em>");
    s = s.replace(/\u0000(\d+)\u0000/g, (m, i) => codes[Number(i)]);
    return s.replace(/\n/g, "<br>");
  }

  const LIST_RE = /^(\s*)([-*•]|\d+[.)])\s+(.*)$/;
  const FENCE_RE = /^\s*```(\w*)\s*$/;
  const HEADING_RE = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
  const HR_RE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
  const TABLE_ROW_RE = /^\s*\|.*\|\s*$/;
  const TABLE_SEP_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

  function splitRow(line) {
    let t = line.trim();
    if (t.startsWith("|")) t = t.slice(1);
    if (t.endsWith("|")) t = t.slice(0, -1);
    return t.split("|").map((c) => c.trim());
  }

  function startsBlock(lines, i) {
    const l = lines[i];
    return FENCE_RE.test(l) || HEADING_RE.test(l) || HR_RE.test(l) || LIST_RE.test(l) || /^\s*>/.test(l) ||
      (TABLE_ROW_RE.test(l) && i + 1 < lines.length && TABLE_SEP_RE.test(lines[i + 1]));
  }

  function render(text) {
    const lines = String(text == null ? "" : text).replace(/\r/g, "").split("\n");
    const out = [];
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) { i++; continue; }

      let m = FENCE_RE.exec(line);
      if (m) {
        const buf = [];
        i++;
        while (i < lines.length && !FENCE_RE.test(lines[i])) buf.push(lines[i++]);
        i++; // closing fence
        out.push(`<pre><code>${esc(buf.join("\n"))}</code></pre>`);
        continue;
      }

      m = HEADING_RE.exec(line);
      if (m) { out.push(`<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`); i++; continue; }

      if (HR_RE.test(line)) { out.push("<hr>"); i++; continue; }

      if (TABLE_ROW_RE.test(line) && i + 1 < lines.length && TABLE_SEP_RE.test(lines[i + 1])) {
        const head = splitRow(line);
        const aligns = splitRow(lines[i + 1]).map((c) => (c.startsWith(":") && c.endsWith(":") ? "center" : c.endsWith(":") ? "right" : ""));
        i += 2;
        const rows = [];
        while (i < lines.length && TABLE_ROW_RE.test(lines[i])) rows.push(splitRow(lines[i++]));
        const cell = (tag, c, k) => `<${tag}${aligns[k] ? ` style="text-align:${aligns[k]}"` : ""}>${inline(c)}</${tag}>`;
        out.push('<div class="table-wrap"><table><thead><tr>' + head.map((c, k) => cell("th", c, k)).join("") + "</tr></thead><tbody>" +
          rows.map((r) => "<tr>" + head.map((_, k) => cell("td", r[k] == null ? "" : r[k], k)).join("") + "</tr>").join("") + "</tbody></table></div>");
        continue;
      }

      if (/^\s*>/.test(line)) {
        const buf = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) buf.push(lines[i++].replace(/^\s*>\s?/, ""));
        out.push(`<blockquote>${inline(buf.join("\n"))}</blockquote>`);
        continue;
      }

      if (LIST_RE.test(line)) {
        const items = [];
        while (i < lines.length) {
          const lm = LIST_RE.exec(lines[i]);
          if (lm) {
            items.push({ indent: lm[1].replace(/\t/g, "    ").length, ordered: /\d/.test(lm[2]), text: lm[3] });
            i++;
          } else if (lines[i].trim() && /^\s+/.test(lines[i]) && items.length) {
            items[items.length - 1].text += "\n" + lines[i].trim(); i++;       // an indented continuation of the previous item
          } else if (!lines[i].trim() && i + 1 < lines.length && LIST_RE.test(lines[i + 1]) &&
                     (LIST_RE.exec(lines[i + 1])[1].length > 0 || /\d/.test(LIST_RE.exec(lines[i + 1])[2]) === items[items.length - 1].ordered)) {
            i++;                                                               // a blank line inside one list (a bullet list followed by a numbered one is two lists)
          } else break;
        }
        let html = "";
        const stack = [];
        const open = (it) => { const tag = it.ordered ? "ol" : "ul"; html += `<${tag}>`; stack.push({ indent: it.indent, tag }); };
        for (const it of items) {
          if (!stack.length) open(it);
          else if (it.indent > stack[stack.length - 1].indent) open(it);
          else {
            while (stack.length > 1 && it.indent < stack[stack.length - 1].indent) { html += `</li></${stack.pop().tag}>`; }
            html += "</li>";
          }
          html += `<li>${inline(it.text)}`;
        }
        while (stack.length) html += `</li></${stack.pop().tag}>`;
        out.push(html);
        continue;
      }

      const buf = [line];
      i++;
      while (i < lines.length && lines[i].trim() && !startsBlock(lines, i)) buf.push(lines[i++]);
      out.push(`<p>${inline(buf.join("\n"))}</p>`);
    }
    return out.join("");
  }

  const api = { render, inline, esc };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.cjMarkdown = api;
})(typeof window !== "undefined" ? window : globalThis);
