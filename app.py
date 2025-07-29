from fastapi import FastAPI, Request, Response, HTTPException
import httpx
import logging

app = FastAPI()

# vLLM-serve base URL
VLLM_BASE_URL = "http://10.72.144.171:7070"

# Set of valid API keys
VALID_API_KEYS = {
    "b8e1e7f2-94a9-43c6-9b2e-0d2c9cf7f1c1",
    "3f7a2d45-a6b4-4eab-9549-94e2f8b8e2cd"
}

logger = logging.getLogger("uvicorn.error")

def get_api_key(request: Request):
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()

def validate_key(api_key):
    """Check if the API key is valid."""
    return api_key and api_key in VALID_API_KEYS

def filter_headers(headers):
    """Remove hop-by-hop headers from response."""
    excluded = {
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade"
    }
    return {k: v for k, v in headers.items() if k.lower() not in excluded}

async def forward_request(request: Request, method: str, url: str, require_auth: bool = False):
    # API Key validation if required
    if require_auth:
        api_key = get_api_key(request)
        if not validate_key(api_key):
            logger.warning("Forbidden: Invalid or missing API key")
            raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")
    # Prepare request headers for forwarding
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("authorization", None)  # Don't forward your proxy's auth header
    headers.pop("x-api-key", None)
    # Forward request
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            if method == "POST":
                body = await request.body()
                resp = await client.post(url, content=body, headers=headers)
            elif method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                raise HTTPException(status_code=405, detail="Method not allowed")
    except httpx.RequestError as e:
        logger.error(f"Error connecting to vLLM-serve: {e}")
        raise HTTPException(status_code=502, detail="Error connecting to backend")
    logger.info(f"Proxied {url}: {resp.status_code}")
    # Relay the response (status, headers, body) back to the client
    response_headers = filter_headers(resp.headers)
    logger.info(f"Proxy: {url} for {api_key}")
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=response_headers
    )

@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request):
    url = f"{VLLM_BASE_URL}/v1/chat/completions"
    return await forward_request(request, "POST", url, require_auth=True)

@app.post("/v1/completions")
async def proxy_completions(request: Request):
    url = f"{VLLM_BASE_URL}/v1/completions"
    return await forward_request(request, "POST", url, require_auth=True)

@app.get("/v1/models")
async def proxy_models(request: Request):
    url = f"{VLLM_BASE_URL}/v1/models"
    return await forward_request(request, "GET", url, require_auth=False)