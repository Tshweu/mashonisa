from fastapi import FastAPI, Request, Response, HTTPException
import httpx
import re

app = FastAPI()
BACKEND_API = "http://localhost:8000"  # Your actual API

# Simple list of malicious patterns to check in payload
SUSPICIOUS_PATTERNS = [
    r"(\bor\b|\band\b).*(=|like)",  # SQL keywords
    r"(\bselect\b|\bdrop\b|\bunion\b)",  # SQL injection
    r"<script.*?>",  # XSS
    r"base64,",  # Possible data URI payload
]

def inspect_payload(content: str) -> bool:
    """Return True if payload is clean, False if suspicious"""
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            return False
    return True

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    headers = dict(request.headers)
    body = await request.body()

    # Inspect headers and payload
    content = body.decode("utf-8", errors="ignore")

    if not inspect_payload(content):
        raise HTTPException(status_code=403, detail="Blocked by DPI filter")

    # Forward the request to the real backend
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=f"{BACKEND_API}/{path}",
            headers=headers,
            content=body
        )

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )
