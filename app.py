import os
import logging
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException
import httpx

app = FastAPI()

# vLLM-serve base URL
VLLM_BASE_URL = "http://10.72.144.171:7070"

# Configuration file path
API_KEYS_CONFIG_PATH = "/app/config/api-keys.conf"
# Log file path
ACCESS_LOG_PATH = "/app/logs/logs.txt"

# Store valid API keys and their group names
VALID_API_KEYS = {}

# Set up logging for application errors
app_logger = logging.getLogger("uvicorn.error")

# Set up logging for access logs
access_logger = logging.getLogger("access_logger")
access_logger.setLevel(logging.INFO)
# Ensure the logs directory exists
os.makedirs(os.path.dirname(ACCESS_LOG_PATH), exist_ok=True)
access_handler = logging.FileHandler(ACCESS_LOG_PATH)
access_formatter = logging.Formatter('%(message)s') # We'll format the message directly
access_handler.setFormatter(access_formatter)
access_logger.addHandler(access_handler)
access_logger.propagate = False # Prevent logs from going to root logger

def load_api_keys():
    """Load API keys and group names from the configuration file."""
    try:
        VALID_API_KEYS.clear()
        with open(API_KEYS_CONFIG_PATH, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'): # Ignore empty lines and comments
                    try:
                        api_key, grpname = line.split(',', 1)
                        VALID_API_KEYS[api_key.strip()] = grpname.strip()
                    except ValueError:
                        app_logger.warning(f"Skipping malformed line in {API_KEYS_CONFIG_PATH}: {line}")
        app_logger.info(f"Loaded {len(VALID_API_KEYS)} API keys from {API_KEYS_CONFIG_PATH}")
    except FileNotFoundError:
        app_logger.error(f"Configuration file not found: {API_KEYS_CONFIG_PATH}. Exiting.")
        # As per user's request, exit if config file is not found
        import sys
        sys.exit(1)
    except Exception as e:
        app_logger.error(f"Error loading API keys from {API_KEYS_CONFIG_PATH}: {e}. Exiting.")
        import sys
        sys.exit(1)

@app.on_event("startup")
async def startup_event():
    load_api_keys()

def validate_api(api_key):
    """Validate an API key against the stored valid keys and group names."""
    load_api_keys()
    return api_key and api_key in [key[0] for key in VALID_API_KEYS]


def get_api_key_and_group(request: Request):
    """Extract Bearer token and find its group from Authorization header."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None, None
    api_key = auth_header.split(" ", 1)[1].strip()
    grpname = VALID_API_KEYS.get(api_key)
    return api_key, grpname

async def forward_request(request: Request, method: str, url: str, require_auth: bool = False):
    api_key = None
    grpname = "N/A" # Default for unauthenticated requests or invalid keys
    http_code = 500 # Default to internal server error

    try:
        # API Key validation if required
        if require_auth:
            api_key, grpname = get_api_key_and_group(request)
            if not api_key or grpname is None:
                app_logger.warning("Forbidden: Invalid or missing API key")
                http_code = 403
                raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")

        # Prepare request headers for forwarding
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("authorization", None)  # Don't forward your proxy's auth header
        headers.pop("x-api-key", None)

        # Forward request
        async with httpx.AsyncClient(timeout=30) as client:
            if method == "POST":
                body = await request.body()
                resp = await client.post(url, content=body, headers=headers)
            elif method == "GET":
                resp = await client.get(url, headers=headers)
            else:
                http_code = 405
                raise HTTPException(status_code=405, detail="Method not allowed")
        
        http_code = resp.status_code
        app_logger.info(f"Proxied {url}: {resp.status_code}")
        
        # Relay the response (status, headers, body) back to the client
        response_headers = filter_headers(resp.headers)
        
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=response_headers
        )
    except httpx.RequestError as e:
        app_logger.error(f"Error connecting to vLLM-serve: {e}")
        http_code = 502
        raise HTTPException(status_code=502, detail="Error connecting to backend")
    except HTTPException as e:
        # Re-raise the HTTPException to be handled by FastAPI
        raise e
    finally:
        # Log the request details
        timestamp = datetime.now().isoformat()
        source_ip = request.client.host if request.client else "unknown"
        endpoint_accessed = request.url.path
        
        # Ensure grpname is "N/A" if api_key is not found, even for authenticated endpoints
        if require_auth and api_key and grpname is None:
            grpname = "N/A (Invalid Key)"
        elif not require_auth:
            api_key = "N/A"
            grpname = "N/A"

        access_log_entry = f"{timestamp},{source_ip},{api_key or 'N/A'},{grpname},{endpoint_accessed},{http_code}"
        access_logger.info(access_log_entry)


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