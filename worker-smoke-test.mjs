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
assert.equal(health.firebaseConfigured, true);
assert.equal(health.searchEnabled, false);
assert.equal(health.tavilyConfigured, false);
assert.equal(health.serperConfigured, false);
assert.deepEqual(health.serperBindings, []);

response = await worker.fetch(new Request('https://ghost.example/api/chat', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ messages: [{ role: 'user', content: 'Hello' }] })
}), { ASSETS: assets });
assert.equal(response.status, 500);
assert.match((await response.json()).error, /NVIDIA_API_KEY is not configured/);

response = await worker.fetch(request('/api/health'), { ASSETS: assets, NVIDIA_API_KEY: 'test-only' });
health = await response.json();
assert.equal(health.nvidiaConfigured, true);
assert.equal(health.searchEnabled, false);
assert.equal(health.tavilyConfigured, false);
assert.equal(health.serperConfigured, false);

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
let lastNvidiaBody = null;
globalThis.fetch = async (url, options = {}) => {
  const target = String(url);
  if (target.includes('securetoken@system.gserviceaccount.com')) {
    return new Response(JSON.stringify({ keys: [jwk] }), { headers: { 'cache-control': 'max-age=3600' } });
  }
  if (target === 'https://api.tavily.com/search') throw new Error('Tavily must not be called');
  if (target === 'https://google.serper.dev/search') {
    if (upstreamMode === 'search-down' || upstreamMode === 'serper-down') return new Response('temporarily unavailable', { status: 503 });
    return new Response(JSON.stringify({ organic: [{
      title: 'ChatClaud Search via Serper', link: 'https://example.org/release-notes',
      snippet: 'Fallback search result snippet.'
    }] }), { headers: { 'content-type': 'application/json' } });
  }
  if (target === 'https://example.org/release-notes') {
    return new Response('<html><body><nav>Navigation ignored</nav><main><h1>Release notes</h1><p>Verified page text from the website.</p></main><script>ignoreThisScript()</script></body></html>', {
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }
  if (target.includes('integrate.api.nvidia.com')) {
    if (upstreamMode === 'busy') return new Response('overloaded', { status: 429 });
    lastNvidiaBody = JSON.parse(options.body);
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
  assert.deepEqual(events[1], { type: 'status', stage: 'answer', label: 'Формулирую ответ…' });
  assert.deepEqual(events[2], { type: 'status', stage: 'reasoning', label: 'Reasoning…' });
  assert.deepEqual(events[3], { type: 'token', text: 'Hello ' });
  assert.deepEqual(events[4], { type: 'token', text: 'from Nemotron.' });
  assert.deepEqual(events[5], { type: 'done' });
  assert.doesNotMatch(streamText, /private reasoning must not be forwarded/);
  assert.doesNotMatch(streamText, /Searching the web/);
  assert.doesNotMatch(streamText, /"type":"sources"/);

  // Smart search should run for a freshness-sensitive request, read the result page,
  // emit source cards, and pass fetched page text to Nemotron.
  response = await worker.fetch(new Request('https://ghost.example/api/chat', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'Find the latest news today about ChatClaud Search' }] })
  }), {
    ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper'
  });
  assert.equal(response.status, 200);
  const searchStream = await response.text();
  assert.match(searchStream, /"type":"sources"/);
  assert.match(searchStream, /"provider":"Serper"/);
  assert.match(searchStream, /ChatClaud Search via Serper/);
  assert.match(lastNvidiaBody.messages.map((m) => m.content).join('\n'), /Verified page text from the website/);
  assert.doesNotMatch(lastNvidiaBody.messages.map((m) => m.content).join('\n'), /Navigation ignored|ignoreThisScript/);

  // Russian search imperatives should trigger web search even without "в интернете".
  upstreamMode = 'ok';
  response = await worker.fetch(new Request('https://ghost.example/api/chat', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'Поищи информацию про последние обновления ChatClaud' }] })
  }), { ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper' });
  assert.equal(response.status, 200);
  const russianSearchStream = await response.text();
  assert.match(russianSearchStream, /"type":"sources"/);
  assert.match(lastNvidiaBody.messages.map((m) => m.content).join('\n'), /Verified page text from the website/);

  // Explicit forceSearch allows the client to request search for any prompt.
  response = await worker.fetch(new Request('https://ghost.example/api/chat', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'Explain this concept briefly' }], forceSearch: true })
  }), { ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper' });
  assert.equal(response.status, 200);
  const forcedSearchStream = await response.text();
  assert.match(forcedSearchStream, /"type":"sources"/);

  // Serper is the only search provider and returns source cards.
  upstreamMode = 'ok';
  response = await worker.fetch(new Request('https://ghost.example/api/chat', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'Find the latest news today about ChatClaud Search' }] })
  }), { ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper' });
  assert.equal(response.status, 200);
  const serperStream = await response.text();
  assert.match(serperStream, /"provider":"Serper"/);
  assert.match(serperStream, /"fallbackUsed":false/);
  assert.match(serperStream, /"type":"sources"/);
  assert.match(lastNvidiaBody.messages.map((m) => m.content).join('\\n'), /Verified page text from the website/);

  // If Serper fails, expose a clear failure status and do not fabricate live evidence.
  upstreamMode = 'serper-down';
  response = await worker.fetch(new Request('https://ghost.example/api/chat', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'Find the latest news today about ChatClaud Search' }] })
  }), { ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper' });
  assert.equal(response.status, 200);
  const failedSearchStream = await response.text();
  assert.match(failedSearchStream, /"stage":"search_failed"/);
  assert.match(failedSearchStream, /"ok":false/);
  assert.match(lastNvidiaBody.messages.map((m) => m.content).join('\n'), /automatic live web search failed/i);
  assert.match(lastNvidiaBody.messages.map((m) => m.content).join('\n'), /Serper returned HTTP 503/);
  upstreamMode = 'ok';

  // The app-level rate limit returns the agreed busy contract with a 150-second retry delay.
  const h2 = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: jwk.kid }));
  const p2 = b64url(JSON.stringify({
    aud: 'toypsig-2953f', iss: 'https://securetoken.google.com/toypsig-2953f',
    sub: 'ghost-rate-user', iat: now, exp: now + 3600
  }));
  const input2 = `${h2}.${p2}`;
  const sig2 = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', pair.privateKey, new TextEncoder().encode(input2));
  const token2 = `${input2}.${Buffer.from(sig2).toString('base64url')}`;
  const envRateLimited = { ASSETS: assets, NVIDIA_API_KEY: 'test-only', RATE_LIMIT_PER_MIN: '1' };
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
  assert.deepEqual(providerBusy[2], {
    type: 'error', code: 'busy',
    message: 'Server is full right now. Please wait and try again in 2.5 minutes.',
    retryAfterSec: 150
  });
} finally {
  globalThis.fetch = originalFetch;
}

response = await worker.fetch(request('/api/health'), {
  ASSETS: assets, NVIDIA_API_KEY: 'test-only', SERPER_API_KEY: 'test-serper'
});
health = await response.json();
assert.equal(health.tavilyConfigured, false);

response = await worker.fetch(request('/'), { ASSETS: assets });
assert.equal(await response.text(), 'Ghost AI UI');
console.log('Cloudflare Worker smoke tests passed');
