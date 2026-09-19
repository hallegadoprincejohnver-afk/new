# Clear Processor API

Standalone URL-processing API for Clear.

## What it does

- Resolves normal HTTP(S) redirects.
- Follows 301/302/303/307/308 chains manually.
- Handles simple HTML meta-refresh redirects.
- Blocks private, loopback, link-local, multicast, and other non-public destination IPs.
- Supports an optional target-host allowlist.
- Uses an API key for processing endpoints.
- Has rate limiting and a bounded in-memory queue.
- Can asynchronously POST results to the existing Clear callback when configured.

## What it deliberately does not do

This service does not solve CAPTCHA/Turnstile, defeat Cloudflare or anti-bot checks, bypass authentication, or execute arbitrary destination JavaScript. When a destination requires human verification, the API reports that state instead of trying to defeat it.

## Endpoints

GET /health

POST /resolve

Header: x-api-key: <API_SECRET>

Body:
{
  "url": "https://example.com/"
}

POST /process

Header: x-api-key: <API_SECRET>

Body:
{
  "guild_id": "...",
  "channel_id": "...",
  "message_id": "...",
  "url": "https://example.com/"
}

When CALLBACK_URL is configured, /process sends processing/success/error callbacks.

## Render environment

- API_SECRET (required)
- CALLBACK_URL (optional)
- CALLBACK_SECRET (optional)
- ALLOWED_TARGET_HOSTS (optional, comma-separated)
- MAX_REDIRECTS (default 10)
- REQUEST_TIMEOUT_MS (default 12000)
- MAX_BODY_BYTES (default 512000)
- MAX_CONCURRENCY (default 3)
- RATE_LIMIT (default 60)
- RATE_WINDOW_MS (default 60000)

The service listens on PORT and binds to 0.0.0.0 for Render.
