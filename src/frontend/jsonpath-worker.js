import { runJsonPath } from "./jsonpath-engine.js";

"use strict";

self.onmessage = event => {
  try {
    self.postMessage({ ok: true, ...runJsonPath(event.data?.text, event.data?.path, event.data?.maxResults) });
  } catch (error) {
    self.postMessage({ ok: false, error: error instanceof Error ? error.message : String(error) });
  }
};
