from typing import Optional

from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, UTC
from .conf import settings
from copy import deepcopy

SECRET_KEY = settings.secret_key
ALGORITHM = settings.hash_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.token_expire_minutes

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = deepcopy(data)
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
