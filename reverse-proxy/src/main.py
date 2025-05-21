import logging
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from loguru import logger

from .conf import settings
from .db import RequestLog, SessionLocal
from .detector import is_suspicious
from .forwarder import forward_request

logger.add(sys.stderr, format="{time} {level} {message}", level=logging.INFO)
logger.add("logs_{time}.log")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,  # type: ignore
    allow_origins=[
        f"http://{settings.host}:{settings.port}",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def proxy_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    logger.info(
        "Received request from {client_ip} for {path}",
        client_ip=client_ip,
        path=request.url.path,
    )
    suspicion = is_suspicious(client_ip, request.url.path, dict(request.headers))
    try:
        db = SessionLocal()
        db.add(
            RequestLog(
                ip=client_ip, path=request.url.path, headers=str(request.headers)
            )
        )
        db.commit()

        if suspicion:
            logger.warning(f"Suspicious activity detected: {suspicion}")
            return JSONResponse(status_code=429, content={"error": suspicion})

        logger.info(f"Redirecting to {settings.server_url}")
        response = await forward_request(request, settings.server_url)
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
        )
    except Exception as exc:
        logger.error(f"Error processing request: {exc}")
        return JSONResponse(status_code=500, content={"error": "Internal Server Error"})
    finally:
        db.close()
