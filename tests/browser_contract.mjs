import { LOCAL_SPECS, detectInput, mergeSpecs, runLocal } from "../src/frontend/local-tools.js";
import { compareText } from "../src/frontend/local-diff.js";

const get = async (id, options = {}, count = 1) => (await runLocal(id, options, count)).values;
const password = (await get("password_policy", {
  length: 24,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  min_lowercase: 2,
  min_uppercase: 2,
  min_digits: 2,
  min_symbols: 2,
}))[0];

const sensitiveFieldsAreEphemeral = LOCAL_SPECS.every(spec =>
  [...(spec.inputs || []), ...(spec.options || [])]
    .filter(field => field.sensitive)
    .every(field => field.persist === false),
);

const simulatedRemote = { tools: [
  { id: "jsonpath", label: "Remote JSONPath", inputs: [{ key: "document" }, { key: "query" }] },
  { id: "checksum", inputs: [{ key: "data" }] },
  { id: "password_policy", options: [{ key: "symbols", type: "string" }] },
] };
const merged = Object.fromEntries(mergeSpecs(simulatedRemote).map(spec => [spec.id, spec]));
const fieldKeys = spec => [...(spec.inputs || []), ...(spec.options || [])].map(field => field.key);

const payload = {
  toolCount: LOCAL_SPECS.length,
  sensitiveFieldsAreEphemeral,
  mergedContracts: {
    jsonpath: fieldKeys(merged.jsonpath),
    checksum: fieldKeys(merged.checksum),
    passwordSymbolsType: merged.password_policy.options.find(field => field.key === "symbols")?.type,
  },
  base64: (await get("base64_text", { text: "hello", mode: "encode", padding: true }))[0],
  sha256: (await get("hash", { text: "abc", algorithm: "sha256" }))[0],
  hmac: (await get("hmac", {
    text: "The quick brown fox jumps over the lazy dog",
    key: "key",
    algorithm: "sha256",
  }))[0],
  uuid4: (await get("uuid", { version: 4, hyphens: true }))[0],
  passwordPolicy: {
    length: password.length,
    lower: [...password].filter(char => /[a-z]/.test(char)).length,
    upper: [...password].filter(char => /[A-Z]/.test(char)).length,
    digits: [...password].filter(char => /\d/.test(char)).length,
    symbols: [...password].filter(char => !/[A-Za-z0-9]/.test(char)).length,
  },
  jsonpath: JSON.parse((await get("jsonpath", {
    text: '{"items":[{"id":1,"price":8},{"id":2,"price":12}]}',
    path: "$.items[?@.price < 10].id",
  }))[0]),
  jsonpathRfc: {
    recursive: JSON.parse((await get("jsonpath", {
      text: '{"store":{"book":[{"name":"A"},{"name":"B"}],"bicycle":{"name":"C"}}}',
      path: "$..name",
    }))[0]),
    reverseSlice: JSON.parse((await get("jsonpath", {
      text: '{"items":[{"id":1},{"id":2}]}',
      path: "$.items[::-1].id",
    }))[0]),
    functionFilter: JSON.parse((await get("jsonpath", {
      text: '{"items":[{"name":"A"},{"name":"Long"}]}',
      path: "$.items[?length(@.name) == 1].name",
    }))[0]),
  },
  diffSimilarity: compareText("xabcdef", "yabcdef", { granularity: "char" }).stats,
  jwtDetection: detectInput("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature")[0]?.id,
};

process.stdout.write(JSON.stringify(payload));
