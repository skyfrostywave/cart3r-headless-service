import asyncio
import hmac
import ipaddress
import os
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_NAME = "CART3R Headless Service"
API_KEY = os.getenv("CART3R_API_KEY", "")
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "8"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "12"))
MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT", "5"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "1048576"))

app = FastAPI(title=APP_NAME, version="1.0.0")
semaphore = asyncio.Semaphore(MAX_CONCURRENT)

REDIRECT_CODES = {301, 302, 303, 307, 308}


class InspectRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


def _normalize_and_validate_url(raw_url: str) -> str:
    try:
        parts = urlsplit(raw_url.strip())
        port = parts.port
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")

    if parts.scheme.lower() not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP and HTTPS URLs are allowed")
    if not parts.hostname or parts.username or parts.password:
        raise HTTPException(status_code=400, detail="URL host is missing or contains credentials")
    if port is not None and port not in {80, 443}:
        raise HTTPException(status_code=400, detail="Only ports 80 and 443 are allowed")

    host = parts.hostname.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise HTTPException(status_code=403, detail="Local destinations are blocked")

    # Reject IP literals unless globally routable.
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise HTTPException(status_code=403, detail="Non-public IP destinations are blocked")
    except ValueError:
        pass

    netloc = host
    if ":" in host:  # IPv6 literal
        netloc = f"[{host}]"
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


async def _check_public_dns(url: str) -> None:
    host = urlsplit(url).hostname
    try:
        records = await asyncio.to_thread(
            socket.getaddrinfo, host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Host could not be resolved")

    addresses = {record[4][0] for record in records}
    if not addresses:
        raise HTTPException(status_code=400, detail="Host has no address records")

    # Fail closed if ANY resolved address is not globally routable.
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                raise HTTPException(status_code=403, detail="Host resolves to a non-public address")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid DNS address")


def _check_auth(authorization: str | None) -> None:
    if not API_KEY:
        raise HTTPException(status_code=503, detail="Service is not configured: set CART3R_API_KEY")
    expected = f"Bearer {API_KEY}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
async def health():
    return {"ok": True, "service": APP_NAME, "version": "1.0.0"}


@app.post("/inspect")
async def inspect_link(
    payload: InspectRequest,
    authorization: str | None = Header(default=None),
):
    _check_auth(authorization)

    current = _normalize_and_validate_url(payload.url)
    visited = []

    async with semaphore:
        timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=5.0)
        limits = httpx.Limits(max_connections=MAX_CONCURRENT, max_keepalive_connections=MAX_CONCURRENT)
        headers = {
            "User-Agent": "CART3R-Link-Inspector/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5",
        }

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                limits=limits,
                follow_redirects=False,
                trust_env=False,
                headers=headers,
            ) as client:
                for _ in range(MAX_REDIRECTS + 1):
                    current = _normalize_and_validate_url(current)
                    await _check_public_dns(current)

                    if current in visited:
                        raise HTTPException(status_code=422, detail="Redirect loop detected")
                    visited.append(current)

                    async with client.stream("GET", current) as response:
                        status = response.status_code
                        location = response.headers.get("location")

                        if status in REDIRECT_CODES and location:
                            current = urljoin(current, location)
                            continue

                        # Read only a bounded amount to avoid downloading large files.
                        total = 0
                        async for chunk in response.aiter_bytes():
                            total += len(chunk)
                            if total > MAX_RESPONSE_BYTES:
                                break

                        return {
                            "ok": True,
                            "original_url": payload.url,
                            "destination": str(response.url),
                            "status_code": status,
                            "redirects": max(0, len(visited) - 1),
                            "visited": visited,
                            "note": "This service inspects ordinary HTTP redirects only. It does not solve CAPTCHA, complete ad tasks, or bypass access controls.",
                        }

                raise HTTPException(status_code=422, detail="Too many redirects")
        except HTTPException:
            raise
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Target request timed out")
        except httpx.RequestError:
            raise HTTPException(status_code=502, detail="Could not fetch target URL")
