import logging
import sys
from typing import Optional

import httpx
from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from .db import SessionLocal, GeolocationLog, User
from datetime import datetime
from collections import Counter
from functools import cache
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .auth import verify_password, hash_password, create_access_token
from fastapi import HTTPException, status, Request
from loguru import logger
from fastapi.middleware.cors import CORSMiddleware

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
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
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
    from jose import JWTError, jwt
    from .auth import SECRET_KEY, ALGORITHM

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
    ip: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    logger.info("Received request to geolocate IP: {ip}", ip=ip)
    country = get_country_from_ip(ip)
    log = GeolocationLog(ip=ip, country=country)
    db.add(log)
    db.commit()
    return {"ip": ip, "country": country}


@app.get("/ips-by-country")
def ips_by_country(
    country: str,
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    db: Session = Depends(get_db),
):
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
def top_countries(db: Session = Depends(get_db)):
    logger.info("Received request to get top countries")
    logs = db.query(GeolocationLog).all()
    counter = Counter(log.country for log in logs)
    return counter.most_common(5)


@app.post("/register")
def register(
    form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    if db.query(User).filter(User.username == form.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    user = User(username=form.username, hashed_password=hash_password(form.password))
    db.add(user)
    db.commit()
    return {"msg": "User created successfully"}


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}
