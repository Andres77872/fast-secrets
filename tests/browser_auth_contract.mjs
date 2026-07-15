import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import { LOCAL_BY_ID, runLocal } from "../src/frontend/local-tools.js";

const run = async (id, options) => (await runLocal(id, options)).values[0];
const rejects = async (id, options, pattern) => {
  await assert.rejects(() => run(id, options), pattern);
};
const b64url = value => Buffer.from(value).toString("base64url");
const compactToken = (header, claims, secret) => {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  return `${signingInput}.${createHmac("sha256", secret).update(signingInput).digest("base64url")}`;
};
const hotp = counter => {
  const message = Buffer.alloc(8); message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", "12345678901234567890").update(message).digest();
  const offset = digest.at(-1) & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
};

const secret = "contract-secret";
const token = await run("jwt_encode", {
  claims: JSON.stringify({ sub: "alice" }), header: "{}", secret, algorithm: "HS256",
});
const verified = JSON.parse(await run("jwt_verify", {
  token, secret, allowed_algorithms: "HS256", leeway: 86_400,
}));
assert.equal(verified.verified, true);
await rejects("jwt_verify", { token, secret, allowed_algorithms: "HS512", leeway: 0 }, /allow-list/);
await rejects("jwt_verify", { token, secret, allowed_algorithms: "HS256,RS256", leeway: 0 }, /only HS256/);
await rejects("jwt_verify", { token, secret, allowed_algorithms: "HS256", leeway: 86_401 }, /between 0 and 86400/);
await rejects("jwt_verify", { token, secret, allowed_algorithms: "HS256", leeway: -1 }, /between 0 and 86400/);
await rejects("jwt_debugger", {
  mode: "verify", token, secret, allowed_algorithms: "HS512", clock_skew: 0,
}, /allow-list/);
await rejects("jwt_debugger", {
  mode: "verify", token, secret, allowed_algorithms: "HS256", clock_skew: 86_401,
}, /between 0 and 86400/);
for (const [claims, header] of [["42", "{}"], ["[]", "{}"], ["{}", "true"], ["{}", "null"]]) {
  await rejects("jwt_encode", { claims, header, secret, algorithm: "HS256" }, /JSON object/);
}
await rejects("jwt_debugger", {
  mode: "sign", header: "{}", payload: '"scalar"', secret, algorithm: "HS256",
}, /JSON object/);
await rejects("jwt_encode", {
  claims: "{}", header: '{"alg":"HS512"}', secret, algorithm: "HS256",
}, /conflicts/);
const lowercaseAlgorithmToken = compactToken({ typ: "JWT", alg: "hs256" }, {}, secret);
await rejects("jwt_verify", {
  token: lowercaseAlgorithmToken, secret, allowed_algorithms: "HS256", leeway: 0,
}, /allow-list/);

const otpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const largeCounter = 2_147_483_648;
const generated = JSON.parse(await run("hotp", {
  secret: otpSecret, counter: largeCounter, digits: 6, algorithm: "SHA-1",
  issuer: "Example", account: "alice@example.com",
}));
assert.equal(generated.counter, largeCounter);
assert.equal(generated.code, hotp(largeCounter));
const hotpVerified = JSON.parse(await run("hotp_verify", {
  secret: otpSecret, code: generated.code, counter: largeCounter,
  look_ahead: 0, digits: 6, algorithm: "SHA-1",
}));
assert.equal(hotpVerified.verified, true);
assert.equal(hotpVerified.counter, largeCounter);
await rejects("hotp", { secret: otpSecret, counter: Number.MAX_SAFE_INTEGER + 1 }, /safe integer/);
await rejects("hotp", { secret: otpSecret, counter: 1.5 }, /safe integer/);
await rejects("hotp", { secret: otpSecret, counter: true }, /safe integer/);
await rejects("hotp", { secret: otpSecret, counter: -1 }, /between 0/);
await rejects("hotp", { secret: otpSecret, counter: 0, digits: 5 }, /digits/);
await rejects("hotp", { secret: otpSecret, counter: 0, digits: 7 }, /6 or 8/);
await rejects("hotp", { secret: otpSecret, counter: 0, algorithm: "MD5" }, /algorithm/);
await rejects("hotp_verify", {
  secret: otpSecret, code: "000000", counter: 0, look_ahead: 101,
}, /look-ahead/);
await rejects("totp", { secret: otpSecret, period: 0 }, /period/);

const enrollment = await run("otpauth_build", {
  otp_type: "hotp", secret: otpSecret, issuer: "Example", account: "alice@example.com",
  counter: largeCounter, digits: 6, algorithm: "SHA1",
});
const parsedEnrollment = JSON.parse(await run("otpauth_parse", { uri: enrollment }));
assert.equal(parsedEnrollment.counter, largeCounter);
assert.equal(parsedEnrollment.issuer, "Example");
assert.equal(parsedEnrollment.account, "alice@example.com");
for (const options of [
  { account: "" }, { account: "team:alice" }, { issuer: "Example:Dev" },
  { algorithm: "MD5" }, { digits: 5 }, { period: 0 },
]) {
  await rejects("otpauth_build", {
    otp_type: "totp", secret: otpSecret, issuer: "Example", account: "alice", ...options,
  }, /(empty|colon|algorithm|digits|period)/i);
}
const badUris = [
  "otpauth://totp/?secret=JBSWY3DP",
  "otpauth://totp/account?secret=JBSWY3DP#fragment",
  "otpauth://totp/account?secret=JBSWY3DP&secret=JBSWY3DP",
  "otpauth://hotp/account?secret=JBSWY3DP",
  "otpauth://totp/Issuer%3Ateam%3Aalice?secret=JBSWY3DP",
  "otpauth://totp/%3Aalice?secret=JBSWY3DP",
  "otpauth://totp/account?secret=JBSWY3DP&issuer=Example%3ADev",
  "otpauth://totp/account?secret=JBSWY3DP&algorithm=MD5",
  "otpauth://totp/account?secret=JBSWY3DP&digits=9",
  "otpauth://totp/account?secret=JBSWY3DP&period=0",
];
for (const uri of badUris) await rejects("otpauth_parse", { uri }, /(label|fragment|repeats|counter|colon|issuer|algorithm|digits|period)/i);

for (const value of ["A", "AAA", "AAAAAA"]) await rejects("base32_decode", { value }, /Base32 length/);

const chromiumUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0 Safari/537.36";
assert.equal(JSON.parse(await run("user_agent_hints", { user_agent: chromiumUa }))["Sec-CH-UA-Mobile"], "?0");
for (const control of ["\r", "\n", "\t", "\0", "\u007f", "\u0085"]) {
  await rejects("user_agent_hints", { user_agent: `${chromiumUa}${control}X-Test: injected` }, /control characters/);
}

const dotenvInput = [
  'Z="two words"',
  "A='hash # literal'",
  'ESC="quote: \\" and slash: \\\\"',
  'EMPTY=""',
  "URL=https://example.test/#anchor # comment",
  "",
].join("\n");
const sortedEnv = await run("env", { text: dotenvInput, mode: "sort" });
assert.equal(sortedEnv, [
  'A="hash # literal"',
  'EMPTY=""',
  'ESC="quote: \\" and slash: \\\\"',
  'URL="https://example.test/#anchor"',
  'Z="two words"',
  "",
].join("\n"));
assert.equal(await run("env", { text: sortedEnv, mode: "sort" }), sortedEnv);
const orderedEnv = 'B="two words"\nEMPTY=""\nA=secret\n';
assert.equal(await run("env", { text: orderedEnv, mode: "redact", mask: "MASK" }), "B=MASK\nEMPTY=\nA=MASK\n");
const complexMask = 'hidden value # "quoted"';
const safelyRedacted = await run("env", { text: "A=secret\n", mode: "redact", mask: complexMask });
assert.equal(safelyRedacted, 'A="hidden value # \\"quoted\\""\n');
assert.equal(await run("env", { text: safelyRedacted, mode: "redact", mask: "NEXT" }), "A=NEXT\n");
assert.equal(await run("env", { text: orderedEnv, mode: "example" }), "B=\nEMPTY=\nA=\n");
assert.equal(await run("dotenv", { text: dotenvInput, action: "sort" }), sortedEnv);
await rejects("env", { text: 'A="unterminated', mode: "sort" }, /unterminated quoted value/);
await rejects("env", { text: 'A="value" tail', mode: "redact" }, /unexpected text/);
await rejects("dotenv", { text: "A=secret", action: "redact", mask: "" }, /mask/i);
const inspectedInvalidEnv = JSON.parse(await run("env", { text: "A='unterminated", mode: "inspect" }));
assert.equal(inspectedInvalidEnv.valid, false);
assert.match(inspectedInvalidEnv.errors[0].error, /unterminated/);

const maxNonce = await run("oauth_state", { nbytes: 256 });
assert.ok(maxNonce.length >= 342);
for (const id of ["oauth_state", "oidc_nonce", "csp_nonce"]) await rejects(id, { nbytes: 257 }, /between 16 and 256/);
assert.equal(LOCAL_BY_ID.oauth_state.options[0].max, 256);
assert.equal(LOCAL_BY_ID.hotp.options.find(field => field.key === "counter").max, Number.MAX_SAFE_INTEGER);

process.stdout.write(JSON.stringify({
  jwt: true,
  hotpCounter: generated.counter,
  otpauth: true,
  base32: true,
  userAgent: true,
  dotenv: true,
  nonce: true,
}));
