# primedefender/php

**PrimeDefender** adds a security layer to PHP apps (plain PHP, Slim, or any PSR-15 stack): it inspects incoming requests for common attack patterns, optionally blocks them, and sends structured incidents to your **PrimeDefender bridge** (for example for a live monitoring map).

This package is the PHP counterpart of [`primedefender-client`](https://www.npmjs.com/package/primedefender-client) (Node.js) and [`primedefender-fastapi`](https://pypi.org/project/primedefender-fastapi/) (Python).

## Features

| Detection | Notes |
|-----------|--------|
| SQL injection | Signature-based |
| XSS | Signature-based |
| Brute force | Configurable window on auth paths |
| Path traversal | Signature-based |
| Command injection | Signature-based |
| File inclusion | Signature-based |
| DDoS / flood | Per-IP sliding window |
| Bot activity | User-agent heuristics + rate limit |
| Scanner | UA + path probes + rate limit |
| Suspicious request | Method / query / body heuristics |
| Auth bypass probe | Header / query patterns |
| Excessive encoding | Nested percent-encoding depth |

Blocked requests return JSON with HTTP `403` or `429` as appropriate. Incidents are **POST**ed to the bridge (default path **`/ingest`** if your `PRIMEDEFENDER_BRIDGE_URL` has no path).

## Requirements

- PHP **8.1+**
- PSR-7 / PSR-15 implementations for middleware mode (e.g. `nyholm/psr7` + Slim)
- A running **PrimeDefender bridge** that accepts the incident JSON

## Install

```bash
composer require primedefender/php
```

For PSR-15 middleware (Slim, etc.):

```bash
composer require primedefender/php nyholm/psr7 slim/slim
```

## Environment variables

Set these in the environment (or load a `.env` file **before** the app starts). PHP does not load `.env` automatically — use your framework or `putenv()` / `$_ENV`.

| Variable | Required | Description |
|----------|----------|-------------|
| `PRIMEDEFENDER_BRIDGE_URL` | Yes* | Bridge base URL, e.g. `http://localhost:3000` (path `/ingest` is added if missing) |
| `PRIMEDEFENDER_API_KEY` | Yes* | API key sent as `X-Api-Key` / `Authorization: Bearer` |
| `PRIMEDEFENDER_SITE_ID` | Yes* | Site identifier in payloads |
| `PRIMEDEFENDER_SITE_LAT` | Recommended | Target latitude for map “to” pin |
| `PRIMEDEFENDER_SITE_LON` | Recommended | Target longitude |
| `PRIMEDEFENDER_SITE_REGION_LABEL` | Optional | Human label, e.g. `Indonesia, Bali` → `targetLabel = "{site_id} · {label}"` |
| `PRIMEDEFENDER_PRIVATE_SOURCE_LABEL` | Optional | Label for private/loopback IPs |
| `PRIMEDEFENDER_AUTH_BYPASS_MODE` | Optional | `observe` or `block` (default **block**) |
| `PRIMEDEFENDER_SUSPICIOUS_REQUEST_MODE` | Optional | `observe` or `block` (default **block**) |
| `PRIMEDEFENDER_MAX_ENCODING_LAYERS` | Optional | Max nested percent-encoding depth (default **3**); deeper chains return **403**. Set **0** to disable. |
| `PRIMEDEFENDER_FLOOD_WINDOW_SECONDS` | Optional | Sliding window for the global per-IP rate (default **10**) |
| `PRIMEDEFENDER_FLOOD_MAX_REQUESTS` | Optional | Max requests per IP per window before **429** / `ddos` (default **90**) |
| `PRIMEDEFENDER_FLOOD_EXEMPT_PATHS` | Optional | Comma-separated paths **not** counted toward that limit. If **unset**, defaults to **`/health`**. If set to an **empty** string, **no** paths are exempt. |

\*If bridge URL, API key, or site id is missing, PrimeDefender is a no-op (detections and reporting stay off).

See `.env.example` for tuning knobs (`PRIMEDEFENDER_BODY_CAP_BYTES`, rate limits, GeoIP TTL, per-detection `*_MODE` / `*_ENABLED`, etc.).

The bridge URL is configured only via environment variables (`.env` or server env) — not in code.

## Usage

### Plain PHP

```php
<?php
require 'vendor/autoload.php';

use PrimeDefender\PrimeDefender;

// After setting PRIMEDEFENDER_* env vars
PrimeDefender::guard();

echo 'hello';
```

`guard()` reads the current request from `$_SERVER` and `php://input`. If a detection is blocked, it emits JSON and exits.

### PSR-15 middleware (Slim 4)

```php
use PrimeDefender\PrimeDefender;
use PrimeDefender\Config;
use Slim\Factory\AppFactory;

$app = AppFactory::create();
$settings = Config::fromEnv();

$app->add(PrimeDefender::middleware($settings, $app->getResponseFactory()));
```

Same idea as FastAPI:

```python
app.add_middleware(PrimeDefenderMiddleware)
```

### Optional overrides

```php
PrimeDefender::guard([
    'siteLabel' => 'Indonesia, Bali',
    'authBypassMode' => 'observe',
    'suspiciousRequestMode' => 'block',
]);
```

`siteLabel` aliases `siteRegionLabel`. Mode keys in `blocksDetection()` use snake_case (`ddos`, `brute_force`, etc.).

### Explicit settings (tests or multi-tenant)

```php
$settings = Config::fromEnv();
$middleware = PrimeDefender::middleware($settings, $responseFactory);
```

`Config::loadSettings()` caches env-based settings; call `Config::clearSettingsCache()` to reset.

## Connect to the PrimeDefender bridge

1. Run your bridge (often on port `3000` or behind HTTPS).
2. Set `PRIMEDEFENDER_BRIDGE_URL` in `.env` or server environment, e.g. `http://localhost:3000`.
3. Ensure the bridge exposes **`POST /ingest`** (or set the full URL including path).
4. Use a valid `PRIMEDEFENDER_API_KEY` accepted by the bridge.

Health check (typical): `GET http://localhost:3000/health`.

## Test SQLi / XSS locally

**SQL injection (query)**

```bash
curl "http://127.0.0.1:8010/auth/login?next=' OR 1=1 --"
```

**XSS**

```bash
curl "http://127.0.0.1:8010/?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

**Map labels (optional test headers)**

```bash
curl "http://127.0.0.1:8010/auth/login?next=' OR 1=1 --" \
  -H "X-Prime-Source-Lat: 34.6937" \
  -H "X-Prime-Source-Lon: 135.5023" \
  -H "X-Prime-Source-Label: Japan, Osaka"
```

## Examples

- `examples/plain.php` — minimal `PrimeDefender::guard()` script
- `examples/slim.php` — Slim 4 middleware setup

## License

MIT — see `LICENSE`.
