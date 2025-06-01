from fastapi import FastAPI, Request, Response, HTTPException
import httpx
import re
import logging
from datetime import datetime
import uvicorn  # <-- make sure this is installed

app = FastAPI()
BACKEND_API = "https://itweb2025.onrender.com/dashboard/"  # Forwarding to another app (can adjust)

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dpi_proxy")

def inspect_payload(content: str) -> bool:
    # for pattern in SUSPICIOUS_PATTERNS:
    #     if re.search(pattern, content, re.IGNORECASE):
    #         return False
    return True

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    headers = dict(request.headers)
    body = await request.body()
    content = body.decode("utf-8", errors="ignore")

    logger.info(f"[{datetime.now()}] {request.method} request from {request.client.host}")
    logger.info(f"Path: /{path}")
    logger.info(f"Query: {request.url.query}")
    logger.info(f"Headers: {headers}")
    logger.info(f"Body: {content[:500]}")

    if not inspect_payload(content) or not inspect_payload(request.url.query):
        logger.warning(f"Blocked suspicious request from {request.client.host}")
        raise HTTPException(status_code=403, detail="Blocked by DPI filter")

    headers.pop("host", None)
    async with httpx.AsyncClient() as client:
        response = await client.request(
            method=request.method,
            url=f"{BACKEND_API}",
            headers=headers,
            content=body
        )

    print(response.content)
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers),
    )

# Run the API server on port 8000
if __name__ == "__main__":
    uvicorn.run("dvi:app", host="0.0.0.0", port=8000, reload=True)
