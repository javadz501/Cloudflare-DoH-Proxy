from pathlib import Path

code = r'''/**
 * DoH Proxy Pro - PUBG Mobile / Privacy Edition
 *
 * Cloudflare Worker implementing DNS-over-HTTPS (RFC 8484).
 * Resolver order:
 *   1. Cloudflare
 *   2. Google
 *   3. OpenDNS
 *   4. Control D (p0, unfiltered)
 *   5. Quad9
 *   6. Mullvad
 *   7. RethinkDNS
 *
 * Endpoints:
 *   POST /dns-query
 *   GET  /dns-query?dns=<base64url DNS packet>
 *   GET  /health
 *
 * This Worker improves DNS transport, caching, validation, and resolver
 * failover. It cannot directly optimize PUBG Mobile's in-match UDP route
 * or guarantee lower game ping.
 */

const CONFIG = Object.freeze({
  DNS_PATH: "/dns-query",
  HEALTH_PATH: "/health",

  UPSTREAM_TIMEOUT_MS: 1400,
  MAX_QUERY_BYTES: 4096,
  MAX_RESPONSE_BYTES: 4096,

  CACHE_MIN_TTL: 5,
  CACHE_MAX_TTL: 300,
  CACHE_PREFIX: "https://worker-dns-cache.invalid/v2/",

  ALLOW_ORIGIN: "*",

  RESOLVERS: [
    {
      name: "Cloudflare",
      url: "https://cloudflare-dns.com/dns-query"
    },
    {
      name: "Google",
      url: "https://dns.google/dns-query"
    },
    {
      name: "OpenDNS",
      url: "https://doh.opendns.com/dns-query"
    },
    {
      name: "Control D",
      url: "https://freedns.controld.com/p0"
    },
    {
      name: "Quad9",
      url: "https://dns.quad9.net/dns-query"
    },
    {
      name: "Mullvad",
      url: "https://doh.mullvad.net/dns-query"
    },
    {
      name: "RethinkDNS",
      url: "https://sky.rethinkdns.com/dns-query"
    }
  ]
});

function makeHeaders(extra = {}) {
  return {
    "Access-Control-Allow-Origin": CONFIG.ALLOW_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Accept",
    "Access-Control-Max-Age": "86400",
    "Cache-Control": "no-store",
    ...extra
  };
}

function textResponse(status, message) {
  return new Response(message, {
    status,
    headers: makeHeaders({
      "Content-Type": "text/plain; charset=utf-8"
    })
  });
}

function readU16(data, offset) {
  return (data[offset] << 8) | data[offset + 1];
}

function writeU16(data, offset, value) {
  data[offset] = (value >>> 8) & 0xff;
  data[offset + 1] = value & 0xff;
}

function readU32(data, offset) {
  return (
    data[offset] * 0x1000000 +
    (data[offset + 1] << 16) +
    (data[offset + 2] << 8) +
    data[offset + 3]
  );
}

function writeU32(data, offset, value) {
  data[offset] = (value >>> 24) & 0xff;
  data[offset + 1] = (value >>> 16) & 0xff;
  data[offset + 2] = (value >>> 8) & 0xff;
  data[offset + 3] = value & 0xff;
}

/**
 * Parse a DNS name, including compression pointers.
 * Compression pointers must point backwards as required by DNS encoding.
 */
function parseDnsName(packet, start) {
  let offset = start;
  let nextOffset = -1;
  let jumped = false;
  let jumpCount = 0;
  let expandedLength = 0;
  const labels = [];

  while (true) {
    if (offset >= packet.length) {
      throw new Error("DNS name exceeds packet");
    }

    const length = packet[offset];

    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= packet.length) {
        throw new Error("Truncated DNS compression pointer");
      }

      const pointer =
        ((length & 0x3f) << 8) |
        packet[offset + 1];

      if (pointer >= offset || pointer >= packet.length) {
        throw new Error("Invalid DNS compression pointer");
      }

      if (!jumped) {
        nextOffset = offset + 2;
      }

      jumped = true;
      offset = pointer;
      jumpCount += 1;

      if (jumpCount > 32) {
        throw new Error("Excessive DNS compression depth");
      }

      continue;
    }

    if ((length & 0xc0) !== 0) {
      throw new Error("Unsupported DNS label encoding");
    }

    offset += 1;

    if (length === 0) {
      if (!jumped) {
        nextOffset = offset;
      }
      break;
    }

    if (length > 63 || offset + length > packet.length) {
      throw new Error("Invalid DNS label length");
    }

    let label = "";

    for (let i = 0; i < length; i += 1) {
      const character = packet[offset + i];

      if (character < 0x21 || character > 0x7e) {
        throw new Error("Invalid DNS label character");
      }

      label += String.fromCharCode(character).toLowerCase();
    }

    expandedLength += length + 1;

    if (expandedLength > 254) {
      throw new Error("DNS name is too long");
    }

    labels.push(label);
    offset += length;
  }

  return {
    name: labels.join("."),
    nextOffset
  };
}

function parseDnsQuestion(packet, offset) {
  const parsedName = parseDnsName(packet, offset);
  const end = parsedName.nextOffset;

  if (end + 4 > packet.length) {
    throw new Error("Truncated DNS question");
  }

  return {
    name: parsedName.name,
    type: readU16(packet, end),
    classCode: readU16(packet, end + 2),
    nextOffset: end + 4
  };
}

/**
 * Validate a complete DNS packet and return record offsets.
 * RDATA is treated as opaque bytes; its declared length is strictly checked.
 */
function inspectDnsPacket(packet, expectedResponse) {
  if (
    !(packet instanceof Uint8Array) ||
    packet.length < 12 ||
    packet.length > CONFIG.MAX_RESPONSE_BYTES
  ) {
    throw new Error("Invalid DNS packet size");
  }

  const flags = readU16(packet, 2);
  const qdCount = readU16(packet, 4);
  const anCount = readU16(packet, 6);
  const nsCount = readU16(packet, 8);
  const arCount = readU16(packet, 10);

  const isResponse = (flags & 0x8000) !== 0;

  if (isResponse !== expectedResponse) {
    throw new Error("Invalid DNS QR flag");
  }

  if (((flags >>> 11) & 0x0f) !== 0) {
    throw new Error("Unsupported DNS opcode");
  }

  if (qdCount !== 1) {
    throw new Error("Exactly one DNS question is required");
  }

  const question = parseDnsQuestion(packet, 12);
  let offset = question.nextOffset;
  const records = [];
  let minimumAnswerTtl = Infinity;

  const sections = [
    { count: anCount, answer: true },
    { count: nsCount, answer: false },
    { count: arCount, answer: false }
  ];

  for (const section of sections) {
    for (let i = 0; i < section.count; i += 1) {
      const owner = parseDnsName(packet, offset);
      offset = owner.nextOffset;

      if (offset + 10 > packet.length) {
        throw new Error("Truncated DNS resource record");
      }

      const type = readU16(packet, offset);
      const ttlOffset = offset + 4;
      const ttl = readU32(packet, ttlOffset);
      const dataLength = readU16(packet, offset + 8);

      if (offset + 10 + dataLength > packet.length) {
        throw new Error("Truncated DNS resource data");
      }

      records.push({
        type,
        ttlOffset,
        ttl,
        answer: section.answer
      });

      if (section.answer && type !== 41) {
        minimumAnswerTtl = Math.min(minimumAnswerTtl, ttl);
      }

      offset += 10 + dataLength;
    }
  }

  if (offset !== packet.length) {
    throw new Error("Unexpected trailing DNS data");
  }

  return {
    id: readU16(packet, 0),
    flags,
    rcode: flags & 0x000f,
    truncated: (flags & 0x0200) !== 0,
    answerCount: anCount,
    question,
    records,
    minimumAnswerTtl
  };
}

function sameQuestion(a, b) {
  return (
    a.name === b.name &&
    a.type === b.type &&
    a.classCode === b.classCode
  );
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url DNS parameter");
  }

  const base64 =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);

  const binary = atob(base64);
  const output = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    output[i] = binary.charCodeAt(i);
  }

  return output;
}

async function sha256Hex(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Transaction ID is excluded from the cache key.
 * All other DNS bytes, including flags and EDNS options, remain significant.
 */
async function createCacheKey(packet) {
  const normalized = packet.slice();
  normalized[0] = 0;
  normalized[1] = 0;

  const digest = await sha256Hex(normalized);

  return new Request(
    `${CONFIG.CACHE_PREFIX}${digest}`,
    { method: "GET" }
  );
}

async function readBoundedStream(stream, maxBytes, label) {
  if (!stream) {
    throw new Error(`Empty ${label} body`);
  }

  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const result = await reader.read();

      if (result.done) {
        break;
      }

      total += result.value.byteLength;

      if (total > maxBytes) {
        await reader.cancel();
        throw new RangeError(`${label} exceeds size limit`);
      }

      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const output = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return output;
}

async function readUpstreamBody(response) {
  const declaredLength = Number(
    response.headers.get("Content-Length")
  );

  if (
    Number.isFinite(declaredLength) &&
    declaredLength > CONFIG.MAX_RESPONSE_BYTES
  ) {
    throw new RangeError("Upstream response exceeds size limit");
  }

  return readBoundedStream(
    response.body,
    CONFIG.MAX_RESPONSE_BYTES,
    "Upstream response"
  );
}

/**
 * The timeout remains active until the complete response body is read.
 */
async function queryResolver(resolver, query, expected) {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    CONFIG.UPSTREAM_TIMEOUT_MS
  );

  try {
    const response = await fetch(resolver.url, {
      method: "POST",
      headers: {
        "Accept": "application/dns-message",
        "Content-Type": "application/dns-message"
      },
      body: query,
      signal: controller.signal,
      redirect: "error"
    });

    if (!response.ok) {
      throw new Error(`${resolver.name} HTTP ${response.status}`);
    }

    const contentType = (
      response.headers.get("Content-Type") || ""
    ).toLowerCase();

    if (!contentType.includes("application/dns-message")) {
      throw new Error(`${resolver.name} returned invalid content type`);
    }

    const body = await readUpstreamBody(response);
    const parsed = inspectDnsPacket(body, true);

    if (parsed.id !== expected.id) {
      throw new Error(`${resolver.name} returned mismatched transaction ID`);
    }

    if (!sameQuestion(parsed.question, expected.question)) {
      throw new Error(`${resolver.name} returned mismatched DNS question`);
    }

    if (parsed.truncated) {
      throw new Error(`${resolver.name} returned a truncated DNS response`);
    }

    if (parsed.rcode === 2) {
      throw new Error(`${resolver.name} returned SERVFAIL`);
    }

    return { body, parsed };
  } finally {
    clearTimeout(timeout);
  }
}

function calculateCacheTtl(parsed) {
  if (
    parsed.rcode !== 0 ||
    parsed.answerCount === 0 ||
    !Number.isFinite(parsed.minimumAnswerTtl) ||
    parsed.minimumAnswerTtl <= 0
  ) {
    return 0;
  }

  return Math.min(
    CONFIG.CACHE_MAX_TTL,
    parsed.minimumAnswerTtl
  );
}

/**
 * Decrement all resource-record TTLs by the time spent in the Worker cache.
 * This prevents a cache hit from extending the original DNS TTL.
 */
function decrementPacketTtls(packet, parsed, elapsedSeconds) {
  if (elapsedSeconds <= 0) {
    return packet;
  }

  const output = packet.slice();

  for (const record of parsed.records) {
    if (record.type === 41) {
      continue;
    }

    const remaining = Math.max(0, record.ttl - elapsedSeconds);
    writeU32(output, record.ttlOffset, remaining);
  }

  return output;
}

async function getCachedResponse(cacheKey, queryInfo) {
  try {
    const cached = await caches.default.match(cacheKey);

    if (!cached) {
      return null;
    }

    const storedAt = Number(
      cached.headers.get("X-Worker-Cache-Time")
    );

    if (!Number.isFinite(storedAt) || storedAt <= 0) {
      return null;
    }

    const body = new Uint8Array(
      await cached.arrayBuffer()
    );

    const parsed = inspectDnsPacket(body, true);

    if (
      parsed.rcode !== 0 ||
      parsed.truncated ||
      !sameQuestion(parsed.question, queryInfo.question)
    ) {
      return null;
    }

    const elapsedSeconds = Math.max(
      0,
      Math.floor((Date.now() - storedAt) / 1000)
    );

    const ttl = calculateCacheTtl(parsed);

    if (ttl <= elapsedSeconds) {
      return null;
    }

    const output = decrementPacketTtls(
      body,
      parsed,
      elapsedSeconds
    );

    writeU16(output, 0, queryInfo.id);

    return output;
  } catch (_) {
    return null;
  }
}

async function putCachedResponse(cacheKey, result) {
  const ttl = calculateCacheTtl(result.parsed);

  if (ttl < CONFIG.CACHE_MIN_TTL) {
    return;
  }

  try {
    const body = result.body.slice();

    writeU16(body, 0, 0);

    const cacheResponse = new Response(body, {
      status: 200,
      headers: {
        "Content-Type": "application/dns-message",
        "Cache-Control": `public, max-age=${ttl}`,
        "X-Worker-Cache-Time": String(Date.now())
      }
    });

    await caches.default.put(cacheKey, cacheResponse);
  } catch (_) {
    // Cache failures must not break DNS resolution.
  }
}

async function resolveDns(query, queryInfo) {
  const cacheKey = await createCacheKey(query);

  const cached = await getCachedResponse(
    cacheKey,
    queryInfo
  );

  if (cached) {
    return cached;
  }

  let lastError = null;

  for (const resolver of CONFIG.RESOLVERS) {
    try {
      const result = await queryResolver(
        resolver,
        query,
        queryInfo
      );

      await putCachedResponse(cacheKey, result);

      return result.body;
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error("All DNS resolvers failed");
}

async function readClientQuery(request) {
  const url = new URL(request.url);

  if (request.method === "GET") {
    const parameter = url.searchParams.get("dns");

    if (!parameter) {
      throw new Error("Missing dns parameter");
    }

    const query = decodeBase64Url(parameter);

    if (
      query.length < 12 ||
      query.length > CONFIG.MAX_QUERY_BYTES
    ) {
      throw new RangeError("DNS query size is invalid");
    }

    return query;
  }

  if (request.method === "POST") {
    const contentType = (
      request.headers.get("Content-Type") || ""
    ).toLowerCase();

    if (!contentType.includes("application/dns-message")) {
      throw new TypeError(
        "Content-Type must be application/dns-message"
      );
    }

    const declaredLength = Number(
      request.headers.get("Content-Length")
    );

    if (
      Number.isFinite(declaredLength) &&
      declaredLength > CONFIG.MAX_QUERY_BYTES
    ) {
      throw new RangeError("DNS query exceeds size limit");
    }

    const query = await readBoundedStream(
      request.body,
      CONFIG.MAX_QUERY_BYTES,
      "DNS query"
    );

    if (query.length < 12) {
      throw new Error("DNS query is too short");
    }

    return query;
  }

  throw new TypeError("Method not allowed");
}

function makeHealthResponse() {
  return new Response(
    JSON.stringify({
      status: "ok",
      service: "DoH Proxy Pro",
      protocol: "RFC 8484",
      resolverCount: CONFIG.RESOLVERS.length,
      resolverOrder: CONFIG.RESOLVERS.map(item => item.name),
      note: "Worker is running; upstream resolvers are checked on demand."
    }, null, 2),
    {
      status: 200,
      headers: makeHeaders({
        "Content-Type": "application/json; charset=utf-8"
      })
    }
  );
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: makeHeaders()
      });
    }

    if (
      url.pathname === CONFIG.HEALTH_PATH &&
      request.method === "GET"
    ) {
      return makeHealthResponse();
    }

    if (url.pathname !== CONFIG.DNS_PATH) {
      return textResponse(404, "Not Found");
    }

    if (
      request.method !== "GET" &&
      request.method !== "POST"
    ) {
      return textResponse(405, "Method Not Allowed");
    }

    try {
      const query = await readClientQuery(request);
      const queryInfo = inspectDnsPacket(query, false);

      const answer = await resolveDns(
        query,
        queryInfo
      );

      return new Response(answer, {
        status: 200,
        headers: makeHeaders({
          "Content-Type": "application/dns-message",
          "Content-Length": String(answer.byteLength)
        })
      });
    } catch (error) {
      if (error instanceof TypeError) {
        return textResponse(415, error.message);
      }

      if (error instanceof RangeError) {
        return textResponse(413, "DNS message too large");
      }

      if (error.name === "AbortError") {
        return textResponse(504, "DNS upstream timeout");
      }

      return textResponse(502, "DNS resolution failed");
    }
  }
};
'''

path = Path("/mnt/data/worker.js")
path.write_text(code, encoding="utf-8")
print(f"Created: {path}")
print(f"Size: {path.stat().st_size} bytes")
print(f"Lines: {len(code.splitlines())}")
