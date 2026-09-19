import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import { URL } from "node:url";
import crypto from "node:crypto";
import { chromium } from "playwright";

const PORT = Number(process.env.PORT || 10000);
const API_SECRET = String(process.env.API_SECRET || "").trim();
const CALLBACK_URL = String(process.env.CALLBACK_URL || "").trim();
const CALLBACK_SECRET = String(process.env.CALLBACK_SECRET || "").trim();
const MAX_REDIRECTS = clampInt(process.env.MAX_REDIRECTS, 1, 20, 10);
const REQUEST_TIMEOUT_MS = clampInt(process.env.REQUEST_TIMEOUT_MS, 2_000, 30_000, 12_000);
const MAX_BODY_BYTES = clampInt(process.env.MAX_BODY_BYTES, 16_384, 2_000_000, 512_000);
const MAX_CONCURRENCY = clampInt(process.env.MAX_CONCURRENCY, 1, 16, 3);
const RATE_LIMIT = clampInt(process.env.RATE_LIMIT, 5, 300, 60);
const RATE_WINDOW_MS = clampInt(process.env.RATE_WINDOW_MS, 10_000, 3_600_000, 60_000);
const ALLOWED_TARGET_HOSTS = new Set(
  String(process.env.ALLOWED_TARGET_HOSTS || "")
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean),
);

const queue = [];
let activeJobs = 0;
const rateBuckets = new Map();
const BROWSER_SESSION_TIMEOUT_MS = clampInt(
  process.env.BROWSER_SESSION_TIMEOUT_MS,
  60_000,
  1_800_000,
  600_000,
);
const MAX_BROWSER_SESSIONS = clampInt(
  process.env.MAX_BROWSER_SESSIONS,
  1,
  8,
  3,
);
const browserSessions = new Map();

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function json(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 64_000) throw new Error("request_too_large");
  }
  return JSON.parse(raw || "{}");
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || req.socket.remoteAddress || "unknown";
}

function consumeRateLimit(ip) {
  const now = Date.now();
  const bucket = rateBuckets.get(ip) || [];
  while (bucket.length && bucket[0] <= now - RATE_WINDOW_MS) bucket.shift();
  if (bucket.length >= RATE_LIMIT) {
    rateBuckets.set(ip, bucket);
    return false;
  }
  bucket.push(now);
  rateBuckets.set(ip, bucket);
  if (rateBuckets.size > 5_000) {
    for (const [key, times] of rateBuckets) {
      while (times.length && times[0] <= now - RATE_WINDOW_MS) times.shift();
      if (!times.length) rateBuckets.delete(key);
    }
  }
  return true;
}

function cleanUrl(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const candidate = value.trim().replace(/^<+|>+$/g, "");
  try {
    const u = new URL(candidate);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    if (u.username || u.password) return null;
    u.hash = "";
    return u.toString();
  } catch {
    return null;
  }
}

function isPrivateIp(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const [a, b] = address.split(".").map(Number);
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127 ||
      (a === 169 && b === 254) ||
      a === 0 ||
      a >= 224
    );
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe8") ||
      normalized.startsWith("fe9") ||
      normalized.startsWith("fea") ||
      normalized.startsWith("feb")
    );
  }
  return true;
}

async function resolveSafe(hostname) {
  const lower = hostname.toLowerCase().replace(/\.$/, "");
  if (lower === "localhost" || lower.endsWith(".localhost")) {
    throw new Error("blocked_private_host");
  }

  if (ALLOWED_TARGET_HOSTS.size) {
    let allowed = false;
    for (const allowedHost of ALLOWED_TARGET_HOSTS) {
      if (lower === allowedHost || lower.endsWith("." + allowedHost)) {
        allowed = true;
        break;
      }
    }
    if (!allowed) throw new Error("host_not_allowed");
  }

  if (net.isIP(lower)) {
    if (isPrivateIp(lower)) throw new Error("blocked_private_ip");
    return [{ address: lower, family: net.isIP(lower) }];
  }

  const answers = await dns.promises.lookup(lower, { all: true, verbatim: true });
  if (!answers.length) throw new Error("dns_resolution_failed");
  for (const answer of answers) {
    if (isPrivateIp(answer.address)) throw new Error("blocked_private_ip");
  }
  return answers;
}

function safeBrowserAction(action) {
  const allowed = new Set([
    "click",
    "dblclick",
    "move",
    "wheel",
    "press",
    "type",
    "reload",
    "back",
    "forward",
  ]);
  return typeof action === "string" && allowed.has(action);
}

async function closeBrowserSession(session) {
  if (!session || session.closed) return;
  session.closed = true;
  browserSessions.delete(session.id);
  await session.context.close().catch(() => {});
  await session.browser.close().catch(() => {});
}

function getBrowserSession(id) {
  const session = browserSessions.get(id);
  if (!session || session.closed) return null;
  if (Date.now() - session.last_activity > BROWSER_SESSION_TIMEOUT_MS) {
    void closeBrowserSession(session);
    return null;
  }
  return session;
}

async function createBrowserSession(url) {
  if (browserSessions.size >= MAX_BROWSER_SESSIONS) {
    throw new Error("browser_session_limit");
  }

  const initial = cleanUrl(url);
  if (!initial) throw new Error("invalid_url");

  const parsedInitial = new URL(initial);
  await resolveSafe(parsedInitial.hostname);

  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    locale: "en-US",
  });

  const page = await context.newPage();

  await page.route("**/*", async (route) => {
    const requestUrl = route.request().url();

    if (!/^https?:$/i.test(new URL(requestUrl).protocol)) {
      await route.continue();
      return;
    }

    try {
      await resolveSafe(new URL(requestUrl).hostname);
      await route.continue();
    } catch {
      await route.abort("blockedbyclient");
    }
  });

  const id = crypto.randomUUID();
  const session = {
    id,
    browser,
    context,
    page,
    initial_url: initial,
    current_url: initial,
    created_at: Date.now(),
    last_activity: Date.now(),
    ready: false,
    closed: false,
  };

  browserSessions.set(id, session);

  page.on("framenavigated", () => {
    session.current_url = page.url();
    session.last_activity = Date.now();
  });

  page.on("close", () => {
    session.closed = true;
    browserSessions.delete(id);
  });

  try {
    await page.goto(initial, {
      waitUntil: "domcontentloaded",
      timeout: REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    if (!page.url()) {
      await closeBrowserSession(session);
      throw error;
    }
  }

  session.current_url = page.url();
  return session;
}

async function browserSessionSnapshot(session) {
  session.last_activity = Date.now();
  session.current_url = session.page.url();

  const body = await session.page.content().catch(() => "");
  const title = await session.page.title().catch(() => "");
  const challenge = looksLikeChallenge(
    title + "\n" + body,
    {},
  );

  session.ready = !challenge;

  const screenshot = await session.page.screenshot({
    type: "png",
    fullPage: false,
  });

  return {
    ok: true,
    session_id: session.id,
    ready: session.ready,
    current_url: session.current_url,
    title,
    screenshot_base64: screenshot.toString("base64"),
  };
}

async function performBrowserAction(session, body) {
  if (!safeBrowserAction(body?.action)) {
    throw new Error("unsupported_browser_action");
  }

  session.last_activity = Date.now();
  const page = session.page;

  switch (body.action) {
    case "click":
      if (!Number.isFinite(Number(body.x)) || !Number.isFinite(Number(body.y))) {
        throw new Error("invalid_click_coordinates");
      }
      await page.mouse.click(Number(body.x), Number(body.y));
      break;

    case "dblclick":
      if (!Number.isFinite(Number(body.x)) || !Number.isFinite(Number(body.y))) {
        throw new Error("invalid_click_coordinates");
      }
      await page.mouse.dblclick(Number(body.x), Number(body.y));
      break;

    case "move":
      if (!Number.isFinite(Number(body.x)) || !Number.isFinite(Number(body.y))) {
        throw new Error("invalid_move_coordinates");
      }
      await page.mouse.move(Number(body.x), Number(body.y));
      break;

    case "wheel":
      await page.mouse.wheel(
        Number.isFinite(Number(body.delta_x)) ? Number(body.delta_x) : 0,
        Number.isFinite(Number(body.delta_y)) ? Number(body.delta_y) : 0,
      );
      break;

    case "press":
      if (typeof body.key !== "string" || !body.key.trim()) {
        throw new Error("missing_key");
      }
      await page.keyboard.press(body.key);
      break;

    case "type":
      if (typeof body.text !== "string") {
        throw new Error("missing_text");
      }
      await page.keyboard.type(body.text.slice(0, 2_000));
      break;

    case "reload":
      await page.reload({ waitUntil: "domcontentloaded", timeout: REQUEST_TIMEOUT_MS }).catch(() => {});
      break;

    case "back":
      await page.goBack({ waitUntil: "domcontentloaded", timeout: REQUEST_TIMEOUT_MS }).catch(() => {});
      break;

    case "forward":
      await page.goForward({ waitUntil: "domcontentloaded", timeout: REQUEST_TIMEOUT_MS }).catch(() => {});
      break;
  }

  await page.waitForTimeout(250).catch(() => {});
  return browserSessionSnapshot(session);
}

setInterval(() => {
  const cutoff = Date.now() - BROWSER_SESSION_TIMEOUT_MS;
  for (const session of browserSessions.values()) {
    if (session.last_activity <= cutoff) {
      void closeBrowserSession(session);
    }
  }
}, 30_000).unref();

function requestOnce(target, bodyNeeded = true) {
  return new Promise(async (resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      reject(new Error("invalid_url"));
      return;
    }

    let addresses;
    try {
      addresses = await resolveSafe(parsed.hostname);
    } catch (error) {
      reject(error);
      return;
    }

    const address = addresses[0];
    const isHttps = parsed.protocol === "https:";
    const client = isHttps ? https : http;
    const port = parsed.port
      ? Number(parsed.port)
      : isHttps
        ? 443
        : 80;

    const headers = {
      "User-Agent": "Clear-Processor/1.0",
      "Accept": "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.8",
      "Cache-Control": "no-cache",
      Host: parsed.host,
      Connection: "close",
    };

    const options = {
      protocol: parsed.protocol,
      hostname: address.address,
      port,
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers,
      timeout: REQUEST_TIMEOUT_MS,
      lookup(_hostname, _options, callback) {
        callback(null, address.address, address.family);
      },
    };

    if (isHttps) options.servername = parsed.hostname;

    const req = client.request(options, (res) => {
      const chunks = [];
      let total = 0;

      res.on("data", (chunk) => {
        if (!bodyNeeded) return;
        total += chunk.length;
        if (total <= MAX_BODY_BYTES) chunks.push(chunk);
      });

      res.on("end", () => {
        const body = bodyNeeded ? Buffer.concat(chunks).toString("utf8") : "";
        resolve({
          status: res.statusCode || 0,
          headers: res.headers,
          body,
          truncated: total > MAX_BODY_BYTES,
        });
      });
    });

    req.on("timeout", () => req.destroy(new Error("request_timeout")));
    req.on("error", reject);
    req.end();
  });
}

function absolutize(baseUrl, location) {
  try {
    return cleanUrl(new URL(location, baseUrl).toString());
  } catch {
    return null;
  }
}

function looksLikeChallenge(body, headers) {
  const text = String(body || "").toLowerCase();
  const server = String(headers?.server || "").toLowerCase();
  return (
    server.includes("cloudflare") ||
    text.includes("cf-chl-") ||
    text.includes("challenge-platform") ||
    text.includes("just a moment...") ||
    text.includes("verify you are human") ||
    text.includes("captcha") ||
    text.includes("turnstile")
  );
}

function extractMetaRefresh(body, baseUrl) {
  const match = String(body || "").match(
    /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"']+)/i,
  );
  if (!match?.[1]) return null;
  return absolutize(baseUrl, match[1].trim());
}

async function resolvePublicUrl(inputUrl) {
  let current = cleanUrl(inputUrl);
  if (!current) throw new Error("invalid_url");

  const chain = [];
  const seen = new Set();

  for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
    if (seen.has(current)) throw new Error("redirect_loop");
    seen.add(current);
    chain.push(current);

    const response = await requestOnce(current, true);
    const location = response.headers.location;

    if ([301, 302, 303, 307, 308].includes(response.status) && location) {
      const next = absolutize(current, location);
      if (!next) throw new Error("invalid_redirect_location");
      current = next;
      continue;
    }

    if (looksLikeChallenge(response.body, response.headers)) {
      return {
        ok: false,
        code: "human_verification_required",
        message: "The destination requires browser or human verification. This processor does not bypass that protection.",
        final_url: current,
        redirects: chain.length - 1,
      };
    }

    const meta = extractMetaRefresh(response.body, current);
    if (meta && meta !== current) {
      current = meta;
      continue;
    }

    return {
      ok: true,
      final_url: current,
      redirects: chain.length - 1,
      status: response.status,
      content_type: String(response.headers["content-type"] || ""),
      truncated: response.truncated,
    };
  }

  throw new Error("too_many_redirects");
}

function requireAuth(req) {
  if (!API_SECRET) return false;
  const supplied = String(req.headers["x-api-key"] || req.headers["x-trw-worker-secret"] || req.headers["x-processor-secret"] || "");
  return supplied && supplied === API_SECRET;
}

async function sendCallback(payload) {
  if (!CALLBACK_URL) return;
  const url = cleanUrl(CALLBACK_URL);
  if (!url) throw new Error("invalid_callback_url");

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(CALLBACK_SECRET ? { "x-trw-worker-secret": CALLBACK_SECRET } : {}),
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10_000),
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`callback_http_${response.status}: ${body.slice(0, 300)}`);
  }
}

async function runJob(job) {
  const started = Date.now();

  if (CALLBACK_URL) {
    await sendCallback({
      guild_id: job.guild_id,
      channel_id: job.channel_id,
      message_id: job.message_id,
      stage: "processing",
    }).catch((error) => console.error("processing callback failed:", error.message));
  }

  try {
    const result = await resolvePublicUrl(job.url);
    const payload = {
      guild_id: job.guild_id,
      channel_id: job.channel_id,
      message_id: job.message_id,
      stage: result.ok ? "success" : "error",
      ...(result.ok ? { result: result.final_url } : { error: result.message }),
      diagnostics: {
        redirects: result.redirects,
        elapsed_ms: Date.now() - started,
        code: result.ok ? "resolved" : result.code,
      },
    };

    if (CALLBACK_URL) {
      await sendCallback(payload).catch((error) =>
        console.error("result callback failed:", error.message),
      );
    }

    console.log(JSON.stringify({
      event: "job_finished",
      message_id: job.message_id,
      ok: result.ok,
      code: result.ok ? "resolved" : result.code,
      elapsed_ms: Date.now() - started,
    }));
  } catch (error) {
    const message = String(error instanceof Error ? error.message : error).slice(0, 700);
    if (CALLBACK_URL) {
      await sendCallback({
        guild_id: job.guild_id,
        channel_id: job.channel_id,
        message_id: job.message_id,
        stage: "error",
        error: message,
      }).catch((callbackError) =>
        console.error("error callback failed:", callbackError.message),
      );
    }

    console.error(JSON.stringify({
      event: "job_failed",
      message_id: job.message_id,
      error: message,
      elapsed_ms: Date.now() - started,
    }));
  }
}

function pumpQueue() {
  while (activeJobs < MAX_CONCURRENCY && queue.length) {
    const job = queue.shift();
    activeJobs += 1;
    runJob(job)
      .catch((error) => console.error("job crash:", error))
      .finally(() => {
        activeJobs -= 1;
        pumpQueue();
      });
  }
}

async function handle(req, res) {
  const pathname = new URL(req.url, "http://localhost").pathname;

  if (req.method === "GET" && pathname === "/health") {
    return json(res, 200, {
      ok: true,
      service: "clear-processor-api",
      queue_depth: queue.length,
      active_jobs: activeJobs,
      callback_configured: Boolean(CALLBACK_URL),
    });
  }

  if (req.method === "GET" && pathname === "/") {
    return json(res, 200, {
      ok: true,
      service: "clear-processor-api",
      endpoints: ["/health", "/resolve", "/process"],
    });
  }

  if (req.method === "POST" && pathname === "/browser/session") {
    if (!requireAuth(req)) {
      return json(res, 401, { ok: false, error: "unauthorized" });
    }

    const ip = getClientIp(req);
    if (!consumeRateLimit(ip)) {
      return json(res, 429, { ok: false, error: "rate_limited" });
    }

    let body;
    try {
      body = await readJson(req);
    } catch {
      return json(res, 400, { ok: false, error: "invalid_json" });
    }

    try {
      const session = await createBrowserSession(body?.url);
      return json(res, 201, await browserSessionSnapshot(session));
    } catch (error) {
      return json(res, 400, {
        ok: false,
        error: String(error instanceof Error ? error.message : error),
      });
    }
  }

  const browserMatch = pathname.match(/^\/browser\/session\/([a-f0-9-]+)(?:\/(action|close))?$/i);
  if (browserMatch && (req.method === "GET" || req.method === "POST")) {
    if (!requireAuth(req)) {
      return json(res, 401, { ok: false, error: "unauthorized" });
    }

    const session = getBrowserSession(browserMatch[1]);
    if (!session) {
      return json(res, 404, { ok: false, error: "browser_session_not_found" });
    }

    if (req.method === "GET") {
      try {
        return json(res, 200, await browserSessionSnapshot(session));
      } catch {
        return json(res, 500, { ok: false, error: "browser_snapshot_failed" });
      }
    }

    if (browserMatch[2] === "close") {
      await closeBrowserSession(session);
      return json(res, 200, { ok: true, closed: true });
    }

    let body;
    try {
      body = await readJson(req);
    } catch {
      return json(res, 400, { ok: false, error: "invalid_json" });
    }

    try {
      return json(res, 200, await performBrowserAction(session, body));
    } catch (error) {
      return json(res, 400, {
        ok: false,
        error: String(error instanceof Error ? error.message : error),
      });
    }
  }

  if ((req.method === "POST" && (pathname === "/resolve" || pathname === "/process"))) {
    if (!requireAuth(req)) {
      return json(res, 401, { ok: false, error: "unauthorized" });
    }

    const ip = getClientIp(req);
    if (!consumeRateLimit(ip)) {
      return json(res, 429, { ok: false, error: "rate_limited" });
    }

    let body;
    try {
      body = await readJson(req);
    } catch {
      return json(res, 400, { ok: false, error: "invalid_json" });
    }

    const url = cleanUrl(body?.url);
    if (!url) {
      return json(res, 400, { ok: false, error: "missing_or_invalid_url" });
    }

    if (pathname === "/resolve") {
      try {
        const result = await resolvePublicUrl(url);
        return json(res, result.ok ? 200 : 409, result);
      } catch (error) {
        return json(res, 400, {
          ok: false,
          error: String(error instanceof Error ? error.message : error),
        });
      }
    }

    const guild_id = String(body?.guild_id || "");
    const channel_id = String(body?.channel_id || "");
    const message_id = String(body?.message_id || "");

    if (!guild_id || !channel_id || !message_id) {
      return json(res, 400, {
        ok: false,
        error: "missing_guild_channel_or_message_id",
      });
    }

    if (queue.length >= 100) {
      return json(res, 503, { ok: false, error: "queue_full" });
    }

    queue.push({ guild_id, channel_id, message_id, url, queued_at: Date.now() });
    pumpQueue();

    return json(res, 202, {
      ok: true,
      accepted: true,
      queue_position: queue.length,
    });
  }

  return json(res, 404, { ok: false, error: "not_found" });
}

http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error("unhandled request error:", error);
    if (!res.headersSent) json(res, 500, { ok: false, error: "internal_error" });
    else res.end();
  });
}).listen(PORT, "0.0.0.0", () => {
  console.log(`Clear Processor API listening on ${PORT}`);
});
