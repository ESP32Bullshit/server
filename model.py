from sqlalchemy import Column, String
from database import Base
import random
import string

def generate_12_digit_uid():
    return ''.join(random.choices(string.digits, k=12))

class User(Base):
    __tablename__ = "users"

    # 12-digit auto-generated user-id
    id = Column(String(12), primary_key=True, default=generate_12_digit_uid)
    username = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=True)
    details = Column(String, nullable=True)
    address = Column(String, nullable=True)
    public_key = Column(String, nullable=True)
