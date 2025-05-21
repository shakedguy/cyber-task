import asyncio
import httpx
import random
import string


async def syn_flood(url: str, access_token: str, rate: int):
    async def flood(client: httpx.AsyncClient):
        try:
            res = await client.get(
                url=url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=2,
            )
            print(res.text)
        except:
            pass

    async with httpx.AsyncClient() as session:
        await asyncio.gather(*[flood(session) for _ in range(rate)])


async def brute_force(url: str, access_token: str, rate: int):
    async def brute(client: httpx.AsyncClient):
        random_path = "".join(random.choices(string.ascii_letters + string.digits, k=8))
        try:
            res = await client.get(
                url=f"{url}/{random_path}",
                headers={
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=2,
            )
            print(res.text)
        except:
            pass

    async with httpx.AsyncClient() as session:
        await asyncio.gather(*[brute(session) for _ in range(rate)])


async def header_flood(url: str, access_token: str, rate: int):
    async def flood(client: httpx.AsyncClient):
        headers = {
            f"X-Random-{i}": "".join(random.choices(string.ascii_letters, k=10))
            for i in range(10)
        }
        headers["Authorization"] = f"Bearer {access_token}"
        try:
            res = await client.get(url, headers=headers, timeout=2)
            print(res.text)
        except:
            pass

    async with httpx.AsyncClient() as session:
        await asyncio.gather(*[flood(session) for _ in range(rate)])
