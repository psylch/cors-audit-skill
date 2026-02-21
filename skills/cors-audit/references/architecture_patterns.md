# CORS Architecture Patterns

Detailed CORS strategy and configuration examples for each architecture type.

---

## Pattern 1: Same-Origin (No CORS Needed)

**Architecture:** Frontend and API served from the same domain and port.

```
Browser → https://app.example.com (serves both HTML and /api/*)
```

**Strategy:** No CORS configuration required. All requests are same-origin.

**When this applies:**
- Single-server monolith (e.g., Django/Rails serving templates + API)
- Frontend built and served by the same backend process

**Caveat:** If the frontend dev server runs on a different port (e.g., `localhost:3000` → `localhost:8000`), CORS IS needed during development. Use a dev proxy or enable CORS in dev mode only.

---

## Pattern 2: Simple Cross-Origin

**Architecture:** Frontend on domain A, API on domain B, no gateway in between.

```
Browser (https://app.example.com) → https://api.example.com
```

**Strategy:** Backend handles CORS. No gateway to manage.

**Backend configuration (single allowed origin):**

```python
# FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

```javascript
// Express
app.use(cors({
  origin: 'https://app.example.com',
  credentials: true,
}));
```

**When to use:** Simple projects without a reverse proxy layer.

**Tradeoffs:**
- Simple to set up
- Backend must handle CORS for every consumer change
- No central control if multiple backends exist

---

## Pattern 3: Gateway-Proxied (Recommended)

**Architecture:** A reverse proxy (Caddy, Nginx, Traefik) sits in front of both frontend and backend. All traffic goes through one domain.

```
Browser → https://app.example.com (Gateway)
           ├── /api/* → backend:8080
           └── /*     → frontend:3000
```

**Strategy:** Gateway handles all CORS. Backend CORS disabled in production.

**Gateway configuration (Caddy example):**

```caddyfile
:8080 {
    route {
        # Preflight
        @cors_preflight method OPTIONS
        handle @cors_preflight {
            header Access-Control-Allow-Origin "https://host-app.example.com"
            header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
            header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization"
            header Access-Control-Allow-Credentials "true"
            header Access-Control-Max-Age "86400"
            respond "" 204
        }

        # CORS headers for all responses
        header Access-Control-Allow-Origin "https://host-app.example.com"
        header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
        header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization"
        header Access-Control-Allow-Credentials "true"

        # API proxy
        handle /api/* {
            reverse_proxy backend:8080
        }

        # Frontend proxy
        reverse_proxy frontend:3000
    }
}
```

**Gateway configuration (Nginx example):**

```nginx
server {
    listen 80;
    server_name app.example.com;

    # CORS headers
    add_header Access-Control-Allow-Origin "https://host-app.example.com" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization" always;
    add_header Access-Control-Allow-Credentials "true" always;

    # Preflight
    if ($request_method = OPTIONS) {
        add_header Access-Control-Max-Age 86400;
        add_header Content-Length 0;
        return 204;
    }

    location /api/ {
        proxy_pass http://backend:8080;
        # Strip upstream CORS headers to prevent duplicates
        proxy_hide_header Access-Control-Allow-Origin;
        proxy_hide_header Access-Control-Allow-Methods;
        proxy_hide_header Access-Control-Allow-Headers;
        proxy_hide_header Access-Control-Allow-Credentials;
    }

    location / {
        proxy_pass http://frontend:3000;
    }
}
```

**Backend dev/prod toggle (FastAPI example):**

```python
import os

# Production: CORS handled by gateway. Dev: enable locally.
if os.getenv("ENABLE_CORS", "").lower() in ("1", "true", "yes"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

**When to use:** Any project with a reverse proxy. This is the recommended pattern for most production deployments.

**Why this is best practice:**
- Single source of truth for CORS
- Backend code stays clean, no CORS logic in business code
- Easy to update allowlist without redeploying backend
- Consistent CORS behavior across all backends behind the gateway

---

## Pattern 4: Micro-App Embedded

**Architecture:** An application is embedded as a micro-app (e.g., Qiankun, single-spa) inside a host application on a different domain.

```
Host app (https://main-site.com)
  └── embeds micro-app from https://micro.example.com
        └── micro-app calls https://micro.example.com/api/*
```

**Key insight:** When the micro-app runs inside the host, the browser's `Origin` header is the **host domain** (`https://main-site.com`), not the micro-app domain. This is the source of most micro-app CORS issues.

**Strategy:** Gateway-proxied (Pattern 3) with the host domain as the allowed origin.

**Critical configuration points:**

1. **Gateway `Access-Control-Allow-Origin`:** Must be set to the **host domain** (e.g., `https://main-site.com`), not the micro-app domain

2. **Frontend API base URL:** Must be an **absolute URL** to the gateway:
   ```typescript
   // WRONG: relative path resolves to host domain, not micro-app domain
   const API_BASE = '/api';
   // When embedded in main-site.com, this becomes:
   // https://main-site.com/api → 404 (main site doesn't have /api route)

   // CORRECT: absolute URL to micro-app's gateway
   const API_BASE = 'https://micro.example.com/api';
   // Always points to the right backend regardless of embedding context
   ```

3. **Environment variable strategy:**
   ```
   # .env.development (local dev, no embedding)
   VITE_API_BASE_URL=http://localhost:8000

   # Production (Zeabur/Vercel/etc. env vars)
   VITE_API_BASE_URL=https://micro.example.com
   ```

4. **Frontend code must handle missing env var gracefully:**
   ```typescript
   // Use nullish coalescing (??) not logical OR (||)
   // ?? only falls back on null/undefined, not empty string
   const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '';
   ```

**Common micro-app mistakes:**
- Using `Access-Control-Allow-Origin: *` — works but prevents credentials and is less secure
- Using relative API paths — breaks when embedded because origin changes
- Setting origin to micro-app domain instead of host domain
- Forgetting that the micro-app's static assets (JS/CSS) also need CORS headers for cross-origin loading

---

## Pattern 5: Multi-Consumer API (Dynamic Origin)

**Architecture:** An API is consumed by multiple known domains (e.g., main site, partner sites, internal tools).

```
https://app-a.example.com  ─┐
https://app-b.example.com  ─┼→ https://api.example.com
https://partner.other.com  ─┘
```

**Strategy:** Dynamic origin reflection — check the request `Origin` against a whitelist and echo back the matched origin.

**Why not just use `*`?**
- `*` cannot be used with `Access-Control-Allow-Credentials: true`
- `*` is overly permissive for production

**Backend implementation (FastAPI):**

```python
# Option A: Regex-based (built-in CORSMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https://.*\.example\.com$|^https://partner\.other\.com$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

```python
# Option B: Explicit list
ALLOWED_ORIGINS = [
    "https://app-a.example.com",
    "https://app-b.example.com",
    "https://partner.other.com",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Gateway implementation (Caddy with dynamic origin):**

```caddyfile
# Caddy does not natively support dynamic origin reflection.
# Workaround: use a map or handle per-origin.
# For complex multi-origin needs, prefer handling in the backend.
```

**Gateway implementation (Nginx with dynamic origin):**

```nginx
# Dynamic origin reflection using map
map $http_origin $cors_origin {
    default "";
    "https://app-a.example.com" "$http_origin";
    "https://app-b.example.com" "$http_origin";
    "https://partner.other.com" "$http_origin";
}

server {
    add_header Access-Control-Allow-Origin $cors_origin always;
    add_header Access-Control-Allow-Credentials "true" always;
    # ... other headers
}
```

**When to use:** APIs consumed by 3+ distinct domains, or when partner domains need access.

**Tradeoffs:**
- More complex configuration
- Origin list must be maintained
- Regex patterns can be error-prone (test thoroughly)
- Consider: would an API gateway with built-in CORS management (e.g., Kong, AWS API Gateway) be simpler?

---

## Decision Flowchart

```
Is the frontend served from the same origin as the API?
├── Yes → Pattern 1 (No CORS needed)
└── No
    ├── Is there a reverse proxy/gateway in front?
    │   ├── Yes → Is the app embedded as a micro-app?
    │   │   ├── Yes → Pattern 4 (Micro-app, gateway handles CORS with host domain)
    │   │   └── No  → Pattern 3 (Gateway-proxied, gateway handles CORS)
    │   └── No
    │       ├── Does the API serve multiple consumer domains?
    │       │   ├── Yes → Pattern 5 (Dynamic origin reflection)
    │       │   └── No  → Pattern 2 (Simple cross-origin, backend handles CORS)
    │       └── Consider adding a gateway for Pattern 3
    └── Note: Development environments often need temporary CORS
        regardless of production pattern (use ENABLE_CORS toggle)
```
