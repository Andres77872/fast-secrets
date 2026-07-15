import { exec } from "./vendor/jsonpath-rfc9535/index.js";

const MAX_DOCUMENT_BYTES = 256 * 1024;
const MAX_QUERY_BYTES = 16 * 1024;
const MAX_RESULTS = 500;
const MAX_OUTPUT_BYTES = 1024 * 1024;
const encoder = new TextEncoder();

export function runJsonPath(documentText, expression, requestedLimit = MAX_RESULTS) {
  const text = String(documentText ?? "");
  const path = String(expression ?? "$ ").trim();
  if (encoder.encode(text).length > MAX_DOCUMENT_BYTES) {
    throw new Error("JSONPath input is limited to 256 KiB");
  }
  if (!path || encoder.encode(path).length > MAX_QUERY_BYTES) {
    throw new Error("JSONPath queries must be between 1 byte and 16 KiB");
  }

  let document;
  try { document = JSON.parse(text); }
  catch (error) { throw new Error(`Invalid JSON: ${error.message}`); }

  const limit = Math.max(1, Math.min(Number(requestedLimit) || MAX_RESULTS, MAX_RESULTS));
  const values = [];
  const stop = {};
  let truncated = false;
  try {
    exec(document, path, value => {
      if (values.length >= limit) {
        truncated = true;
        throw stop;
      }
      values.push(value);
    });
  } catch (error) {
    if (error !== stop) throw error;
  }

  const result = JSON.stringify(values, null, 2);
  if (encoder.encode(result).length > MAX_OUTPUT_BYTES) {
    throw new Error("JSONPath output exceeds the 1 MiB browser limit");
  }
  return { result, count: values.length, truncated };
}
