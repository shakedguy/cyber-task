from typing import Annotated

import typer
import asyncio
from src.main import syn_flood, brute_force, header_flood
import httpx

app = typer.Typer()


@app.command()
def attack(
    _type: Annotated[
        str,
        typer.Option("--type", "-t", help="Type of attack: syn, brute, header"),
    ],
    url: Annotated[
        str, typer.Option("--url", "-u", help="Target URL (e.g. http://localhost:8000)")
    ],
    rate: Annotated[int, typer.Option("--rate", "-r", help="Number of requests")] = 500,
):
    """
    CLI to attack a web server (for educational use only).
    """
    typer.echo(f"Launching {_type} attack on {url} with {rate} requests...")
    res = httpx.post(
        "http://localhost:9000/register",
        data={"username": "admin", "password": "123456"},
    )
    if res.is_error:
        content = res.text
        if "already registered" not in content:
            typer.echo(content)
            return typer.Abort()
    res = httpx.post(
        "http://localhost:9000/login", data={"username": "admin", "password": "123456"}
    )
    if res.is_error:
        typer.echo(res.text)
        return typer.Abort()

    token = res.json()["access_token"]
    if _type == "syn":
        asyncio.run(syn_flood(url, token, rate))
    elif _type == "brute":
        asyncio.run(brute_force(url, token, rate))
    elif _type == "header":
        asyncio.run(header_flood(url, token, rate))
    else:
        typer.echo("Invalid attack type. Choose: syn, brute, header.")


if __name__ == "__main__":
    app()
