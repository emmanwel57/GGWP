from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import logging
import json

app = FastAPI()

# vLLM-serve base URL
VLLM_BASE_URL = "http://10.72.144.171:7070"

logger = logging.getLogger("uvicorn.error")
logged = False

def get_api_key(request: Request):
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()

def validate_key(api_key):
    """Check if the API key is valid."""
    with open("/app/config/api-keys.conf", "r") as conf_file:
        conf = conf_file.readlines()
        for c in conf:
            c = c.strip()
            key, user = c.split(",")
            if api_key == key:
                return user
        return False

def log_event(log):
    """ Log the event in text file """
    with open("/app/logs/logs.txt", "a") as log_file:
        log_file.write(f"{log}\n")

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

def get_input_count(body_json):
    system_chars = sum(len(m['content']) for m in body_json['messages'] if m['role'] == 'system')  
    user_chars   = sum(len(m['content']) for m in body_json['messages'] if m['role'] == 'user')  
    assistant_chars = sum(len(m['content']) for m in body_json['messages'] if m['role'] == 'assistant')
    return system_chars + user_chars + assistant_chars

#def get_output_count(response):


async def forward_request(request: Request, method: str, url: str, require_auth: bool = False):
    # API Key validation if required
    user = None
    if require_auth:
        api_key = get_api_key(request)
        user = validate_key(api_key)
        if not user:
            logger.warning("Forbidden: Invalid or missing API key")
            log_event(f"NO-API-KEY,UNAUTHORIZED,{request.client.host},{url},HTTP 403,0,0")
            raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")

    # Prepare request headers for forwarding
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("authorization", None)  # Don't forward your proxy's auth header
    headers.pop("x-api-key", None)
    try:
        if method == "POST":
            body = await request.body()
            body_json = json.loads(body)  
            is_stream = body_json.get("stream", False) 
            #logger.info(body_json)
            input_chars = get_input_count(body_json)
            output_chars = 0
            if not is_stream:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(url, content=body, headers=headers)
                    response_headers = filter_headers(resp.headers)
                    logger.info(f"Proxy success for {url} from {request.client.host} of {user}")
                    log_event(f"{api_key},{user},{request.client.host},{url} HTTP:{resp.status_code},{input_chars},{output_chars}")
                    return Response(
                        content=resp.content,
                        status_code=resp.status_code,
                        headers=response_headers
                    )
            else:
                response_headers = None
                output_chars = [0]
                async def iter_stream():  
                    async with httpx.AsyncClient(timeout=None) as client:  
                        async with client.stream("POST", url, content=body, headers=headers) as resp:
                            response_headers = filter_headers(resp.headers)
                            async for chunk in resp.aiter_raw():
                                decoded = chunk.decode('utf-8').removeprefix("data: ").strip()
                                if "[DONE]" in decoded:
                                    log_event(f"{api_key},{user},{request.client.host},{url} HTTP:POST 200,{input_chars},{output_chars[0]}")
                                else:
                                    output_chars[0] += len(json.loads(decoded).get("choices")[0].get("delta").get("content").strip())
                                yield chunk  
                return StreamingResponse(  
                    iter_stream(),
                    headers=response_headers,
                    media_type="text/event-stream"  
                )
                
        elif method == "GET":
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=headers)
                logger.info(f"Proxy success for {url} from {request.client.host} of {user}")
                log_event(f"{api_key},{user},{request.client.host},{url} HTTP:GET 200,0,0")
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=response_headers
                )
        else:
            raise HTTPException(status_code=405, detail="Method not allowed")
    except httpx.RequestError as e:
            logger.error(f"Error connecting to vLLM-serve: {e}")
            raise HTTPException(status_code=502, detail="Error connecting to backend")
    

    

# async def forward_request(request: Request, method: str, url: str, require_auth: bool = False):
#     # API Key validation if required
#     user = None
#     if require_auth:
#         api_key = get_api_key(request)
#         user = validate_key(api_key)
#         if not user:
#             logger.warning("Forbidden: Invalid or missing API key")
#             log.event(f"NO-API-KEY,UNAUTHORIZED,{request.client.host},{url},HTTP 403,0,0")
#             raise HTTPException(status_code=403, detail="Forbidden: Invalid API key")
#         #user = result[1]

#     # Prepare request headers for forwarding
#     headers = dict(request.headers)
#     headers.pop("host", None)
#     headers.pop("authorization", None)  # Don't forward your proxy's auth header
#     headers.pop("x-api-key", None)

#     # Forward request
#     try:
#         async with httpx.AsyncClient(timeout=30) as client:
#             if method == "POST":
#                 body = await request.body()
#                 upstream = client.stream("POST", url, content=body, headers=headers)
#             elif method == "GET":
#                 upstream = client.stream("GET", url, headers=headers)
#             else:
#                 raise HTTPException(status_code=405, detail="Method not allowed")

#             async with upstream as resp:
#                 logger.info(f"Proxy success for {url} from {request.client.host} of {user}")
#                 response_headers = filter_headers(resp.headers)

#                 # If not streaming (e.g., non-SSE), just read and return the whole response
#                 content_type = resp.headers.get("content-type", "")
#                 if not content_type.startswith("text/event-stream"):
#                     full_body = await resp.aread()
#                     return Response(
#                         content=full_body,
#                         status_code=resp.status_code,
#                         headers=response_headers
#                     )

#                 # If streaming (e.g., SSE), stream the response
#                 async def iter_stream():
#                     async for chunk in resp.aiter_text():
#                         yield chunk

#                 return StreamingResponse(
#                     iter_stream(),
#                     status_code=resp.status_code,
#                     headers=response_headers,
#                     media_type="text/event-stream"
#                 )

#     except httpx.RequestError as e:
#         logger.error(f"Error connecting to vLLM-serve: {e}")
#         raise HTTPException(status_code=502, detail="Error connecting to backend")

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