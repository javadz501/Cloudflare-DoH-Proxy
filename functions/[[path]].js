/**
 * DoH Proxy Pro - PUBG Mobile & Privacy Edition
 * Optimized for Cloudflare Pages Functions
 * RFC 8484-compliant with True Parallel Racing, Validation, and Standard Caching.
 */

const CONFIG = Object.freeze({
  DNS_PATH: "/dns-query",
  HEALTH_PATH: "/health",
  STATS_PATH: "/stats",
  UPSTREAM_TIMEOUT_MS: 1800,
  MAX_QUERY_BYTES: 4096,
  MAX_RESPONSE_BYTES: 4096,
  CACHE_MIN_TTL: 5,
  CACHE_MAX_TTL: 3600,
  DEFAULT_CACHE_TTL: 300,
  CACHE_PREFIX: "https://doh-cache.invalid/v1/",
  ALLOW_ORIGIN: "*",
  RESOLVERS: [
    { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "OpenDNS", url: "https://doh.opendns.com/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "ControlD", url: "https://freedns.controld.com/p0", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "Google", url: "https://dns.google/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "RethinkDNS", url: "https://sky.rethinkdns.com/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "Quad9", url: "https://dns.quad9.net/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 },
    { name: "Mullvad", url: "https://doh.mullvad.net/dns-query", healthScore: 100, consecutiveFailures: 0, circuitState: "closed", lastCircuitOpen: 0, avgResponseTime: 0 }
  ]
});

let globalRequestCount = 0;

function responseHeaders(extra = {}) {
  return {
    "Access-Control-Allow-Origin": CONFIG.ALLOW_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    ...extra
  };
}

function httpError(status, message) {
  return new Response(message, {
    status,
    headers: responseHeaders({ "Content-Type": "text/plain; charset=utf-8" })
  });
}

function readU16(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function writeU16(bytes, offset, value) {
  bytes[offset] = (value >>> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

function parseDnsName(packet, start) {
  let offset = start;
  let nextOffset = -1;
  let jumped = false;
  let jumps = 0;
  const labels = [];

  while (true) {
    if (offset >= packet.length) throw new Error("DNS name exceeds packet");
    const length = packet[offset];

    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length) throw new Error("Invalid compression pointer");
      const pointer = ((length & 0x3f) << 8) | packet[offset + 1];
      if (pointer >= packet.length || pointer === offset) throw new Error("Invalid compression pointer");
      if (!jumped) nextOffset = offset + 2;
      jumped = true;
      offset = pointer;
      jumps += 1;
      if (jumps > 32) throw new Error("Excessive compression depth");
      continue;
    }

    if ((length & 0xc0) !== 0) throw new Error("Unsupported DNS label type");
    offset += 1;
    if (length === 0) {
      if (!jumped) nextOffset = offset;
      break;
    }
    if (length > 63 || offset + length > packet.length) throw new Error("Invalid DNS label");

    let label = "";
    for (let i = 0; i < length; i += 1) {
      const character = packet[offset + i];
      if (character < 0x21 || character > 0x7e) throw new Error("Invalid DNS label character");
      label += String.fromCharCode(character).toLowerCase();
    }
    labels.push(label);
    offset += length;
    if (labels.join(".").length > 253) throw new Error("DNS name is too long");
  }

  return { name: labels.join("."), nextOffset };
}

function parseQuestion(packet, offset) {
  const parsedName = parseDnsName(packet, offset);
  const end = parsedName.nextOffset;
  if (end + 4 > packet.length) throw new Error("Truncated DNS question");
  return {
    name: parsedName.name,
    type: readU16(packet, end),
    classCode: readU16(packet, end + 2),
    nextOffset: end + 4
  };
}

function parseDnsPacket(packet, isResponse) {
  if (!(packet instanceof Uint8Array) || packet.length < 12 || packet.length > CONFIG.MAX_RESPONSE_BYTES) {
    throw new Error("Invalid DNS packet size");
  }

  const flags = readU16(packet, 2);
  const qdCount = readU16(packet, 4);
  const anCount = readU16(packet, 6);
  const nsCount = readU16(packet, 8);
  const arCount = readU16(packet, 10);

  if (((flags & 0x8000) !== 0) !== isResponse) throw new Error("Invalid DNS QR flag");
  if (((flags >>> 11) & 0x0f) !== 0) throw new Error("Unsupported DNS opcode");
  if (qdCount !== 1) throw new Error("Exactly one DNS question is required");

  const question = parseQuestion(packet, 12);
  let offset = question.nextOffset;
  const recordCounts = [anCount, nsCount, arCount];

  for (const count of recordCounts) {
    for (let i = 0; i < count; i += 1) {
      const name = parseDnsName(packet, offset);
      offset = name.nextOffset;
      if (offset + 10 > packet.length) throw new Error("Truncated DNS resource record");
      const dataLength = readU16(packet, offset + 8);
      offset += 10;
      if (offset + dataLength > packet.length) throw new Error("Truncated DNS resource data");
      offset += dataLength;
    }
  }

  if (offset !== packet.length) throw new Error("Unexpected trailing DNS data");

  return {
    id: readU16(packet, 0),
    flags,
    rcode: flags & 0x000f,
    answerCount: anCount,
    question
  };
}

function questionsMatch(left, right) {
  return left.name === right.name &&
    left.type === right.type &&
    left.classCode === right.classCode;
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url DNS parameter");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function makeCacheKey(packet) {
  const normalized = packet.slice();
  writeU16(normalized, 0, 0); // Zero out Transaction ID for cache normalization
  const hash = await sha256Hex(normalized);
  return new Request(`${CONFIG.CACHE_PREFIX}${hash}`, { method: "GET" });
}

function calculateCacheTtl(packet) {
  try {
    let offset = parseDnsName(packet, 12).nextOffset + 4;
    const anCount = readU16(packet, 6);
    const nsCount = readU16(packet, 8);
    const arCount = readU16(packet, 10);
    const counts = [anCount, nsCount, arCount];
    let minimumTtl = CONFIG.CACHE_MAX_TTL;

    for (const count of counts) {
      for (let i = 0; i < count; i += 1) {
        const name = parseDnsName(packet, offset);
        offset = name.nextOffset;
        if (offset + 10 > packet.length) break;
        const recordType = readU16(packet, offset);
        const ttl = (packet[offset + 4] * 0x1000000) +
          (packet[offset + 5] << 16) +
          (packet[offset + 6] << 8) +
          packet[offset + 7];
        const dataLength = readU16(packet, offset + 8);
        if (recordType !== 41) minimumTtl = Math.min(minimumTtl, ttl);
        offset += 10 + dataLength;
      }
    }

    if (minimumTtl === CONFIG.CACHE_MAX_TTL || minimumTtl < 0) return CONFIG.DEFAULT_CACHE_TTL;
    return Math.max(CONFIG.CACHE_MIN_TTL, Math.min(CONFIG.CACHE_MAX_TTL, minimumTtl));
  } catch (e) {
    return CONFIG.DEFAULT_CACHE_TTL;
  }
}

function checkCircuitBreaker(resolver) {
  const now = Date.now();
  if (resolver.circuitState === "open") {
    if (now - resolver.lastCircuitOpen > 60000) {
      resolver.circuitState = "half-open";
      return true;
    }
    return false;
  }
  return true;
}

function updateResolverMetrics(resolver, success, responseTime) {
  if (success) {
    resolver.consecutiveFailures = 0;
    resolver.healthScore = Math.min(100, resolver.healthScore + 5);
    resolver.circuitState = "closed";
    resolver.avgResponseTime = resolver.avgResponseTime === 0 ? responseTime : (resolver.avgResponseTime * 0.7) + (responseTime * 0.3);
  } else {
    resolver.consecutiveFailures++;
    resolver.healthScore = Math.max(0, resolver.healthScore - 20);
    if (resolver.consecutiveFailures >= 3) {
      resolver.circuitState = "open";
      resolver.lastCircuitOpen = Date.now();
    }
  }
}

async function queryUpstream(resolver, packet, expected) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("Upstream timeout"), CONFIG.UPSTREAM_TIMEOUT_MS);
  const startTime = Date.now();

  try {
    const upstreamResponse = await fetch(resolver.url, {
      method: "POST",
      headers: {
        "Accept": "application/dns-message",
        "Content-Type": "application/dns-message"
      },
      body: packet,
      signal: controller.signal,
      redirect: "error"
    });

    if (!upstreamResponse.ok) throw new Error(`Upstream HTTP ${upstreamResponse.status}`);
    const contentType = (upstreamResponse.headers.get("Content-Type") || "").toLowerCase();
    if (!contentType.includes("application/dns-message")) throw new Error("Invalid upstream content type");

    const buffer = await upstreamResponse.arrayBuffer();
    const body = new Uint8Array(buffer);
    if (body.length > CONFIG.MAX_RESPONSE_BYTES) throw new Error("Response exceeds size limit");

    const parsed = parseDnsPacket(body, true);
    if (parsed.id !== expected.id || !questionsMatch(parsed.question, expected.question)) {
      throw new Error("Upstream DNS response does not match request");
    }

    const responseTime = Date.now() - startTime;
    updateResolverMetrics(resolver, true, responseTime);
    return { body, parsed, resolverUrl: resolver.url };
  } catch (error) {
    updateResolverMetrics(resolver, false, Date.now() - startTime);
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

async function resolveDns(packet, queryInfo) {
  const cacheKey = await makeCacheKey(packet);
  const cache = caches.default;
  const cached = await cache.match(cacheKey);

  if (cached) {
    const cachedBuffer = await cached.arrayBuffer();
    const cachedBytes = new Uint8Array(cachedBuffer);
    if (cachedBytes.length >= 12) {
      writeU16(cachedBytes, 0, queryInfo.id); // Correct Transaction ID
      try {
        const parsed = parseDnsPacket(cachedBytes, true);
        if (questionsMatch(parsed.question, queryInfo.question)) {
          return cachedBytes;
        }
      } catch (_) {}
    }
  }

  // True Parallel Racing across healthy resolvers
  const eligibleResolvers = CONFIG.RESOLVERS.filter(r => checkCircuitBreaker(r));
  const activeResolvers = eligibleResolvers.length > 0 ? eligibleResolvers : CONFIG.RESOLVERS;

  const controllers = [];
  const promises = activeResolvers.map(resolver => {
    const controller = new AbortController();
    controllers.push(controller);
    return queryUpstream(resolver, packet, queryInfo).catch(err => {
      throw err;
    });
  });

  try {
    const result = await Promise.any(promises);
    // Abort remaining pending requests once a valid response wins
    for (const c of controllers) {
      try { c.abort(); } catch(e) {}
    }

    // Store in Cache
    const ttl = calculateCacheTtl(result.body);
    if (ttl > 0) {
      const cacheBytes = result.body.slice();
      writeU16(cacheBytes, 0, 0);
      const cacheResponse = new Response(cacheBytes, {
        headers: {
          "Content-Type": "application/dns-message",
          "Cache-Control": `public, max-age=${ttl}`
        }
      });
      await cache.put(cacheKey, cacheResponse);
    }

    return result.body;
  } catch (aggregateError) {
    throw new Error("All DNS resolvers failed in parallel racing");
  }
}

async function getDnsPacket(request) {
  const url = new URL(request.url);

  if (request.method === "GET") {
    const value = url.searchParams.get("dns");
    if (!value) throw new Error("Missing dns query parameter");
    const packet = decodeBase64Url(value);
    if (packet.length > CONFIG.MAX_QUERY_BYTES) throw new Error("DNS query exceeds size limit");
    return packet;
  }

  if (request.method === "POST") {
    const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
    if (!contentType.includes("application/dns-message")) throw new TypeError("Content-Type must be application/dns-message");
    const declaredLength = Number(request.headers.get("Content-Length"));
    if (Number.isFinite(declaredLength) && declaredLength > CONFIG.MAX_QUERY_BYTES) {
      throw new RangeError("DNS query exceeds size limit");
    }
    const reader = request.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > CONFIG.MAX_QUERY_BYTES) {
        await reader.cancel();
        throw new RangeError("DNS query exceeds size limit");
      }
      chunks.push(value);
    }
    const packet = new Uint8Array(total);
    let pos = 0;
    for (const chunk of chunks) {
      packet.set(chunk, pos);
      pos += chunk.byteLength;
    }
    if (packet.length === 0) throw new Error("Empty DNS query body");
    return packet;
  }

  throw new TypeError("Method not allowed");
}

function renderHomePage(requestUrl) {
  const url = new URL(requestUrl);
  const dohUrl = `${url.protocol}//${url.hostname}${CONFIG.DNS_PATH}`;
  const statsUrl = `${url.protocol}//${url.hostname}${CONFIG.STATS_PATH}`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pubgmobiledns — Secure DNS over HTTPS</title>
<style>
:root {
  --bg: #0d1117;
  --card: #161b22;
  --border: #30363d;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #4493f8;
  --success: #3fb950;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono: ui-monospace, SFMono-regular, Consolas, monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: var(--font); background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
.container { max-width: 800px; margin: 0 auto; }
h1 { color: var(--accent); margin-bottom: 0.5rem; font-size: 2rem; }
.subtitle { color: var(--muted); margin-bottom: 2rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }
h3 { margin-bottom: 1rem; color: var(--text); font-size: 1.1rem; }
.url-box { background: #010409; border: 1px solid var(--border); padding: 1rem; border-radius: 6px; font-family: var(--mono); color: #a5d6ff; word-break: break-all; margin-bottom: 1rem; }
.btn { background: var(--success); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block; }
.btn:hover { opacity: 0.9; }
.btn-secondary { background: var(--accent); margin-left: 0.5rem; }
ul { padding-left: 1.5rem; color: var(--muted); }
li { margin-bottom: 0.5rem; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ pubgmobiledns</h1>
  <p class="subtitle">Optimized Secure DNS-over-HTTPS Proxy for PUBG Mobile & Privacy</p>

  <div class="card">
    <h3>📍 Your DoH Endpoint URL</h3>
    <div class="url-box" id="dohUrl">${dohUrl}</div>
    <button class="btn" onclick="navigator.clipboard.writeText('${dohUrl}'); alert('Copied to clipboard!');">📋 Copy Endpoint</button>
    <a href="${statsUrl}" class="btn btn-secondary">📊 View Live Statistics</a>
  </div>

  <div class="card">
    <h3>⚙️ Configured Upstream Resolvers (7 Trusted Providers)</h3>
    <ul>
      ${CONFIG.RESOLVERS.map(r => `<li><strong>${r.name}</strong>: <code>${r.url}</code></li>`).join('')}
    </ul>
  </div>

  <div class="card">
    <h3>📱 How to Use</h3>
    <p><strong>Browsers (Firefox, Chrome, Edge):</strong> Go to privacy/security settings, enable Secure DNS, choose Custom, and paste your Endpoint URL.</p>
    <p style="margin-top: 0.8rem;"><strong>Android (Intra / Private DNS):</strong> Paste your Endpoint URL into Intra or Android Private DNS configuration.</p>
  </div>
</div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

function renderStatsPage(requestUrl) {
  const url = new URL(requestUrl);
  const homeUrl = `${url.protocol}//${url.hostname}/`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>pubgmobiledns — Statistics</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #4493f8; --success: #3fb950; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
.container { max-width: 800px; margin: 0 auto; }
h1 { color: var(--accent); margin-bottom: 1rem; }
.card { background: var(--card); border: 1px solid var(--border); padding: 1.5rem; border-radius: 10px; margin-bottom: 1.5rem; }
.val { font-size: 2rem; font-weight: bold; color: var(--accent); font-family: monospace; }
table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; margin-top: 1rem; }
th, td { padding: 1rem; text-align: left; border-bottom: 1px solid var(--border); font-family: monospace; }
th { background: #010409; color: var(--muted); font-family: sans-serif; font-size: 0.85rem; }
.btn { background: var(--success); color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block; margin-top: 1rem; }
</style>
</head>
<body>
<div class="container">
  <h1>📊 Server Statistics</h1>
  <div class="card">
    <h3>Total Handled Requests</h3>
    <div class="val">${globalRequestCount}</div>
  </div>
  <div class="card">
    <h3>Active Upstream Resolvers</h3>
    <table>
      <thead><tr><th>#</th><th>Resolver Name</th><th>Health Score</th><th>Avg Latency</th></tr></thead>
      <tbody>
        ${CONFIG.RESOLVERS.map((r, i) => `<tr><td>${i + 1}</td><td><strong>${r.name}</strong></td><td>${r.healthScore}%</td><td>${r.avgResponseTime ? r.avgResponseTime.toFixed(0) + 'ms' : 'N/A'}</td></tr>`).join('')}
      </tbody>
    </table>
  </div>
  <a href="${homeUrl}" class="btn">← Back to Home</a>
</div>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: responseHeaders() });
  }

  if (url.pathname === "/" && request.method === "GET") {
    return renderHomePage(request.url);
  }

  if (url.pathname === CONFIG.STATS_PATH && request.method === "GET") {
    return renderStatsPage(request.url);
  }

  if (url.pathname === CONFIG.HEALTH_PATH && request.method === "GET") {
    return new Response(JSON.stringify({
      status: "ok",
      service: "pubgmobiledns",
      protocol: "RFC 8484",
      resolverCount: CONFIG.RESOLVERS.length,
      resolverOrder: CONFIG.RESOLVERS.map(item => item.name)
    }, null, 2), {
      status: 200,
      headers: responseHeaders({ "Content-Type": "application/json; charset=utf-8" })
    });
  }

  if (url.pathname !== CONFIG.DNS_PATH) {
    return httpError(404, "Not Found");
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return httpError(405, "Method Not Allowed");
  }

  globalRequestCount++;

  try {
    const packet = await getDnsPacket(request);
    const queryInfo = parseDnsPacket(packet, false);
    const answer = await resolveDns(packet, queryInfo);

    return new Response(answer, {
      status: 200,
      headers: responseHeaders({
        "Content-Type": "application/dns-message",
        "Content-Length": String(answer.byteLength)
      })
    });
  } catch (error) {
    if (error instanceof TypeError) {
      return httpError(415, error.message);
    }
    if (error instanceof RangeError) {
      return httpError(413, "DNS message too large");
    }
    if (error.name === "AbortError") {
      return httpError(504, "DNS upstream timeout");
    }
    return httpError(502, "DNS resolution failed");
  }
}
