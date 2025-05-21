from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, UTC
from .conf import settings

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


class GeolocationLog(Base):  # type: ignore
    __tablename__ = "geolocation_logs"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    country = Column(String, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(UTC), index=True)


class User(Base):  # type: ignore
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)


Base.metadata.create_all(bind=engine)
