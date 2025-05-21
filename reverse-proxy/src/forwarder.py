import httpx

FORWARD_KEY = "forwarded-by-reverse-proxy"


async def forward_request(request, target_url: str):
    async with httpx.AsyncClient() as client:
        resp = await client.request(
            method=request.method,
            url=f"{target_url}{request.url.path}?{request.url.query}",
            headers={**request.headers, "X-Forwarded-For": FORWARD_KEY},
            content=await request.body(),
        )
        return resp
