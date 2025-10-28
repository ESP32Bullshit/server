from sqlalchemy import Column, String
from database import Base
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=True)
    google_id = Column(String, unique=True, nullable=True)
    public_key = Column(String, nullable=True)
