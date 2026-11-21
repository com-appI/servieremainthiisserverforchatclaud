import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';

const workerSource = await readFile(new URL('./_worker.js', import.meta.url), 'utf8');
const workerUrl = `data:text/javascript;base64,${Buffer.from(workerSource).toString('base64')}`;
const { default: worker } = await import(workerUrl);
const assets = { fetch: async () => new Response('Ghost AI UI', { status: 200 }) };
const request = (path) => new Request(`https://ghost.example${path}`);

let response = await worker.fetch(request('/api/health'), { ASSETS: assets });
assert.equal(response.status, 200);
let health = await response.json();
assert.equal(health.ok, true);
assert.equal(health.nvidiaConfigured, false);
assert.deepEqual(health.nvidiaBindings, []);
assert.equal(health.firebaseConfigured, true);

response = await worker.fetch(new Request('https://ghost.example/api/chat', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ messages: [{ role: 'user', content: 'Hello' }] })
}), { ASSETS: assets });
assert.equal(response.status, 503);
assert.match((await response.json()).error, /Cloudflare не передал секрет NVIDIA_API_KEY/);

response = await worker.fetch(request('/api/health'), { ASSETS: assets, NVIDIA_API_KEY: 'test-only' });
health = await response.json();
assert.equal(health.nvidiaConfigured, true);
assert.deepEqual(health.nvidiaBindings, ['NVIDIA_API_KEY']);

response = await worker.fetch(request('/api/health'), { ASSETS: assets, NVIDIA: 'test-only' });
health = await response.json();
assert.equal(health.nvidiaConfigured, true);
assert.deepEqual(health.nvidiaBindings, ['NVIDIA']);

response = await worker.fetch(new Request('https://ghost.example/api/chat', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ messages: [{ role: 'user', content: 'Hello' }] })
}), { ASSETS: assets, NVIDIA_API_KEY: 'test-only' });
assert.equal(response.status, 401);

// Create a short-lived test Firebase JWT to exercise the authenticated stream locally.
const pair = await crypto.subtle.generateKey({
  name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'
}, true, ['sign', 'verify']);
const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
jwk.kid = 'ghost-test-key';
jwk.alg = 'RS256';
jwk.use = 'sig';
const b64url = (value) => Buffer.from(value).toString('base64url');
const now = Math.floor(Date.now() / 1000);
const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid }));
const payload = b64url(JSON.stringify({
  aud: 'toypsig-2953f', iss: 'https://securetoken.google.com/toypsig-2953f',
  sub: 'ghost-test-user', iat: now, exp: now + 3600
}));
const signingInput = `${header}.${payload}`;
const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(signingInput));
const token = `${signingInput}.${Buffer.from(signature).toString('base64url')}`;

const originalFetch = globalThis.fetch;
let upstreamMode = 'ok';
globalThis.fetch = async (url, options = {}) => {
  const target = String(url);
  if (target.includes('securetoken@system.gserviceaccount.com')) {
    return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'cache-control': 'max-age=3600' } });
  }
  if (target.includes('integrate.api.nvidia.com')) {
    if (upstreamMode === 'busy') return new Response('overloaded', { status: 429 });
    const frames = [
      { choices: [{ delta: { reasoning_content: 'private reasoning must not be forwarded' } }] },
      { choices: [{ delta: { content: 'Hello ' } }] },
      { choices: [{ delta: { content: 'from Nemotron.' } }] }
    ].map((packet) => `data: ${JSON.stringify(packet)}\n\n`).join('') + 'data: [DONE]\n\n';
    return new Response(frames, { headers: { 'content-type': 'text/event-stream' } });
  }
  return originalFetch(url, options);
};

const chatRequest = (uidToken = token) => new Request('https://ghost.example/api/chat', {
  method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${uidToken}` },
  body: JSON.stringify({ messages: [{ role: 'user', content: 'Say hello' }] })
});

try {
  response = await worker.fetch(chatRequest(), { ASSETS: assets, NVIDIA_API_KEY: 'test-only' });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /text\/event-stream/);
  const streamText = await response.text();
  const events = streamText.split(/\r?\n\r?\n/).filter(Boolean).map((frame) => JSON.parse(frame.replace(/^data:\s*/, '')));
  assert.deepEqual(events[0], { type: 'status', stage: 'thinking', label: 'Thinking…' });
  assert.deepEqual(events[1], { type: 'status', stage: 'reasoning', label: 'Reasoning…' });
  assert.deepEqual(events[2], { type: 'token', text: 'Hello ' });
  assert.deepEqual(events[3], { type: 'token', text: 'from Nemotron.' });
  assert.deepEqual(events[4], { type: 'done' });
  assert.doesNotMatch(streamText, /private reasoning must not be forwarded/);

  // The app-level rate limit returns the agreed busy contract with a 150-second retry delay.
  const h2 = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid }));
  const p2 = b64url(JSON.stringify({
    aud: 'toypsig-2953f', iss: 'https://securetoken.google.com/toypsig-2953f',
    sub: 'ghost-rate-user', iat: now, exp: now + 3600
  }));
  const input2 = `${h2}.${p2}`;
  const sig2 = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input2));
  const token2 = `${input2}.${Buffer.from(sig2).toString('base64url')}`;
  const envRateLimited = { ASSETS: assets, NVIDIA_API_KEY: 'test-only', RATE_LIMIT_REQUESTS: '1' };
  response = await worker.fetch(chatRequest(token2), envRateLimited);
  assert.equal(response.status, 200);
  await response.text();
  response = await worker.fetch(chatRequest(token2), envRateLimited);
  assert.equal(response.status, 429);
  const busy = await response.json();
  assert.equal(busy.type, 'error');
  assert.equal(busy.code, 'busy');
  assert.equal(busy.retryAfterSec, 150);

  // Provider-side overload is emitted inside the SSE stream with the same contract.
  upstreamMode = 'busy';
  const h3 = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid }));
  const p3 = b64url(JSON.stringify({
    aud: 'toypsig-2953f', iss: 'https://securetoken.google.com/toypsig-2953f',
    sub: 'ghost-provider-busy-user', iat: now, exp: now + 3600
  }));
  const input3 = `${h3}.${p3}`;
  const sig3 = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input3));
  const token3 = `${input3}.${Buffer.from(sig3).toString('base64url')}`;
  response = await worker.fetch(chatRequest(token3), { ASSETS: assets, NVIDIA_API_KEY: 'test-only' });
  assert.equal(response.status, 200);
  const providerBusy = (await response.text()).split(/\r?\n\r?\n/).filter(Boolean).map((frame) => JSON.parse(frame.replace(/^data:\s*/, '')));
  assert.deepEqual(providerBusy[1], {
    type: 'error', code: 'busy',
    message: 'Server is full right now. Please wait and try again in 2.5 minutes.',
    retryAfterSec: 150
  });
} finally {
  globalThis.fetch = originalFetch;
}

response = await worker.fetch(request('/'), { ASSETS: assets });
assert.equal(await response.text(), 'Ghost AI UI');
console.log('Cloudflare Worker smoke tests: 10 passed');
