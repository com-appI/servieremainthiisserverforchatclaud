// Minimal offline tests (no network, no real secrets)
function readEnvString(env, names) {
  if (!env || typeof env !== "object") return "";
  for (const name of names) {
    const raw = env[name];
    if (typeof raw === "string" && raw.trim()) return raw.trim();
    if (raw != null && typeof raw !== "object" && typeof raw !== "function") {
      const s = String(raw).trim();
      if (s) return s;
    }
  }
  return "";
}
function getSerperApiKey(env) {
  return readEnvString(env, ["SERPER_API_KEY", "SERPER_KEY", "SERPER", "SERPER_AIP_KEY", "SERPERAPIKEY"]);
}
function shouldSearchWeb(query, forceSearch = false) {
  if (forceSearch) return true;
  const q = String(query || "").trim();
  if (!q) return false;
  const lower = q.toLowerCase();
  if (/^(hi|hello|hey|yo|привет|здравств|как дела|how are you|who are you|что ты|ты кто|thanks|спасибо|ok|ок|cool|пока|bye)\b/i.test(lower) && q.length < 48) return false;
  const explicit = ["найди","поищи","поиск","новости","сегодня","search","find","информация о","что произошло"];
  if (explicit.some((h) => lower.includes(h))) return true;
  return false;
}

let pass = 0, fail = 0;
function assert(name, cond) {
  if (cond) { pass++; console.log("PASS", name); }
  else { fail++; console.log("FAIL", name); }
}

assert("empty env -> no key", getSerperApiKey({}) === "");
assert("empty string binding -> no key", getSerperApiKey({ SERPER_API_KEY: "" }) === "");
assert("whitespace binding -> no key", getSerperApiKey({ SERPER_API_KEY: "   " }) === "");
assert("valid key", getSerperApiKey({ SERPER_API_KEY: " sk-test " }) === "sk-test");
assert("typo alias", getSerperApiKey({ SERPER_AIP_KEY: "x" }) === "x");
assert("greeting no search", shouldSearchWeb("привет") === false);
assert("force search", shouldSearchWeb("привет", true) === true);
assert("ru search cmd", shouldSearchWeb("Поищи информацию о Firebase") === true);
assert("ru news", shouldSearchWeb("Что произошло сегодня?") === true);
assert("en find", shouldSearchWeb("Find latest news about SpaceX") === true);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
