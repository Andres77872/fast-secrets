"use strict";

const CACHE = "fast-secrets-static-v2-20260715-6";
const SHELL = new Set([
  "/",
  "/docs",
  "/static/api-docs.html",
  "/static/api-docs.css",
  "/static/api-docs.js",
  "/static/index.html",
  "/static/style.css",
  "/static/theme.js",
  "/static/app.js",
  "/static/local-tools.js",
  "/static/local-diff.js",
  "/static/qr-render.js",
  "/static/qrcodegen.js",
  "/static/regex-worker.js",
  "/static/jsonpath-engine.js",
  "/static/jsonpath-worker.js",
  "/static/vendor/jsonpath-rfc9535/index.js",
  "/static/vendor/jsonpath-rfc9535/core/exec.js",
  "/static/vendor/jsonpath-rfc9535/core/path.js",
  "/static/vendor/jsonpath-rfc9535/core/results.js",
  "/static/vendor/jsonpath-rfc9535/core/types.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/comparable.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/comparison-expr.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/filter-query.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/function-argument.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/function-expr.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/logical-expr.js",
  "/static/vendor/jsonpath-rfc9535/core/evaluators/test-expr.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/count.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/length.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/match.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/search.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/types.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/value.js",
  "/static/vendor/jsonpath-rfc9535/core/functions/utils/construct-regex.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/bracketed-selection.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/filter-selector.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/index-selector.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/member-name-shorthand.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/name-selector.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/query.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/segment.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/slice-selector.js",
  "/static/vendor/jsonpath-rfc9535/core/visitors/wildcard-selector.js",
  "/static/vendor/jsonpath-rfc9535/parser/ast.js",
  "/static/vendor/jsonpath-rfc9535/parser/index.js",
  "/static/vendor/jsonpath-rfc9535/parser/parser.js",
  "/static/vendor/jsonpath-rfc9535/utils/assertions.js",
  "/static/vendor/jsonpath-rfc9535/utils/get-type.js",
  "/static/vendor/jsonpath-rfc9535/utils/guards.js",
  "/static/vendor/jsonpath-rfc9535/utils/is-equal.js",
  "/static/vendor/jsonpath-rfc9535/utils/stack.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/array.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/compare.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/node-lists.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/nothing.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/number.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/object.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/primitives.js",
  "/static/vendor/jsonpath-rfc9535/utils/comparers/string.js",
  "/static/words.js",
  "/static/icon.svg",
  "/static/icon-192.png",
  "/static/icon-512.png",
  "/static/icon-maskable.svg",
  "/static/icon-maskable-512.png",
  "/static/manifest.webmanifest",
]);

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll([...SHELL])).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith("fast-secrets-static-") && key !== CACHE).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || !SHELL.has(url.pathname)) return;
  event.respondWith(caches.match(request, { ignoreSearch: true }).then(cached => cached || fetch(request).then(response => {
    if (response.ok && response.type === "basic") caches.open(CACHE).then(cache => cache.put(request, response.clone()));
    return response;
  })));
});
