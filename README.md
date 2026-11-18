# CART3R Headless Service v1.0.0

A small Railway-ready HTTP service for **ordinary HTTP redirect inspection**.
It is intentionally not a CAPTCHA solver or ad-task bypasser.

## Endpoints

- `GET /health` — public health check.
- `POST /inspect` — inspect an HTTP(S) URL and follow standard HTTP redirects.

Example request:

```bash
curl -X POST "https://YOUR-SERVICE.up.railway.app/inspect" \
  -H "Authorization: Bearer YOUR_CART3R_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Deploy to Railway

1. Create a new Railway project and choose **Deploy from GitHub Repo**.
2. Put `main.py`, `requirements.txt`, and `Dockerfile` in the repository root.
3. In Railway → Variables, add:
   - `CART3R_API_KEY` = a long random secret (at least 32 random bytes).
   - Optionally `MAX_REDIRECTS` = `8`.
   - Optionally `REQUEST_TIMEOUT` = `12`.
   - Optionally `MAX_CONCURRENT` = `5`.
4. Deploy. Railway supplies `PORT`; the Dockerfile uses it.
5. Open `https://YOUR-SERVICE.up.railway.app/health`. Expect `{"ok":true,...}`.

Generate a key locally with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Do not paste the API key into chat, source control, or frontend JavaScript.

## Security notes

- Requires an API bearer token for `/inspect`.
- Allows only HTTP/HTTPS and ports 80/443.
- Rejects localhost, private, loopback, link-local, multicast, and other non-global IPs.
- Resolves and checks DNS before each redirect hop; redirects are checked again.
- Does not execute JavaScript, click buttons, solve CAPTCHA, or complete ad tasks.
- Keep this service server-side. Do not expose `CART3R_API_KEY` in browser code.

**Important limitation:** DNS is checked before the HTTP client connects, so a sophisticated DNS-rebinding race is still possible. For a hardened production deployment, add outbound network-level egress rules that deny private, loopback, link-local, and cloud metadata ranges. Do not treat application-level DNS checks alone as a complete SSRF boundary.

## Vercel integration

Do not add a public rewrite that exposes this service without authentication. If you later connect it to Vercel, call `/inspect` only from a server-side route, store the service URL and API key as server-only environment variables, and preserve the existing Cloudflare Turnstile check on the user-facing flow.
