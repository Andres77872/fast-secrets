"use strict";

self.onmessage = event => {
  try {
    const { pattern, text, flags, replacement } = event.data;
    const cleanFlags = [...new Set(String(flags || "").replace(/[^dgimsuvy]/g, ""))].join("");
    const regex = new RegExp(pattern, cleanFlags);
    const matches = [];
    if (cleanFlags.includes("g") || cleanFlags.includes("y")) {
      let match;
      while ((match = regex.exec(text)) && matches.length < 500) {
        matches.push({ match: match[0], index: match.index, groups: [...match].slice(1), named_groups: match.groups || {} });
        if (match[0] === "") regex.lastIndex++;
      }
    } else {
      const match = regex.exec(text);
      if (match) matches.push({ match: match[0], index: match.index, groups: [...match].slice(1), named_groups: match.groups || {} });
    }
    const result = { matches, count: matches.length, truncated: matches.length === 500 };
    if (replacement) result.replacement_preview = text.replace(new RegExp(pattern, cleanFlags), replacement);
    self.postMessage({ ok: true, result });
  } catch (error) {
    self.postMessage({ ok: false, error: error.message || String(error) });
  }
};
