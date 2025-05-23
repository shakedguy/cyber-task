import logging
import sys
from datetime import datetime
from functools import cache
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy import func

from .auth import create_access_token, hash_password, verify_password
from .conf import settings
from .db import GeolocationLog, SessionLocal, User
from jose import JWTError, jwt

from .auth import ALGORITHM, SECRET_KEY

logger.add(sys.stderr, format="{time} {level} {message}", level=logging.INFO)
logger.add("logs_{time}.log")


IP_API_URL = "http://ip-api.com/json/{ip}"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
FORWARD_KEY = "forwarded-by-reverse-proxy"


@cache
def get_country_from_ip(ip: str) -> str:
    with httpx.Client() as client:
        response = client.get(IP_API_URL.format(ip=ip))

        return (
            response.json().get("country", "Unknown")
            if response.is_success
            else "Unknown"
        )


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
async def check_if_coming_from_reverse_proxy(request: Request, call_next):
    if request.headers.get("X-Forwarded-For", "") == FORWARD_KEY:
        logger.info("Request coming from reverse proxy")
        return await call_next(request)

    logger.warning("Request not coming from reverse proxy")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": "Forbidden: invalid or missing reverse proxy header"},
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


@app.get("/geolocate")
async def geolocate(
    ip: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not ip:
        logger.error("IP parameter is required")
        return JSONResponse(
            {"error": "IP parameter is required"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    logger.info("Received request to geolocate IP: {ip}", ip=ip)
    country = get_country_from_ip(ip)
    if not country:
        logger.error("Failed to geolocate IP: {ip}", ip=ip)
        return JSONResponse(
            {"error": "Failed to geolocate IP"},
            status_code=status.HTTP_404_NOT_FOUND,
        )
    log = GeolocationLog(ip=ip, country=country.lower())
    db.add(log)
    db.commit()
    return {"ip": ip, "country": country}


@app.get("/ips-by-country")
def ips_by_country(
    country: str,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not country:
        return JSONResponse(
            {"error": "Country parameter is required"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    country = country.lower()
    logger.info("Received request to get IPs by country: {country}", country=country)
    query = db.query(GeolocationLog).filter(GeolocationLog.country == country)

    if from_time:
        query = query.filter(
            GeolocationLog.timestamp >= datetime.fromisoformat(from_time)
        )
    if to_time:
        query = query.filter(
            GeolocationLog.timestamp <= datetime.fromisoformat(to_time)
        )

    return [log.ip for log in query.all()]


@app.get("/top-countries")
def top_countries(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    logger.info("Received request to get top countries")
    result = (
        db.query(
            GeolocationLog.country, func.count(GeolocationLog.country).label("count")
        )
        .group_by(GeolocationLog.country)
        .order_by(func.count(GeolocationLog.country).desc())
        .limit(5)
        .all()
    )
    result = (
        [{"country": country, "count": count} for country, count in result]
        if result
        else []
    )

    return JSONResponse(result, status_code=status.HTTP_200_OK)


@app.post("/register")
def register(
    form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == form.username).first():
        return JSONResponse(
            {"error": "Username already registered"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    user = User(username=form.username, hashed_password=hash_password(form.password))
    db.add(user)
    db.commit()
    return JSONResponse(
        {"msg": "User created successfully"}, status_code=status.HTTP_201_CREATED
    )


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        return JSONResponse(
            {"error": "Invalid credentials"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    token = create_access_token(data={"sub": user.username})
    return JSONResponse(
        {
            "access_token": token,
            "token_type": "bearer",
        },
        status_code=status.HTTP_200_OK,
    )
