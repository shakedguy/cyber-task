import logging
import sys

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from .db import SessionLocal, RequestLog
from .detector import is_suspicious
from .forwarder import forward_request
from loguru import logger


logger.add(sys.stderr, format="{time} {level} {message}", level=logging.INFO)
logger.add("logs_{time}.log")

app = FastAPI()
TARGET = "http://localhost:8000"  # your real server


@app.middleware("http")
async def proxy_middleware(request: Request, call_next):
    client_ip = request.client.host

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

        logger.info(f"Redirecting to {TARGET}")
        response = await forward_request(request, TARGET)
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
