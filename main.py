from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from model import User
from pydantic import BaseModel

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserCreate(BaseModel):
    username: str
    name: str = None
    details: str = None
    address: str = None
    public_key: str

@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user and generate a 12-digit UID"""
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=user.username,
        name=user.name,
        details=user.details,
        address=user.address,
        public_key=user.public_key
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username
    }


@app.get("/get_user_key")
def get_user_key(user_id: str, db: Session = Depends(get_db)):
    """Fetch the public key of a user by their user_id (UID)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.public_key:
        raise HTTPException(status_code=400, detail="User does not have a public key configured")
    
    # Returning the public key. It is expected to be a 128-character hex string.
    return {"public_key": user.public_key}


@app.get("/user/{user_id}")
def get_user_details(user_id: str, db: Session = Depends(get_db)):
    """Fetch basic details of a user by their UID"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "user_id": user.id,
        "username": user.username,
        "name": user.name,
        "details": user.details,
        "address": user.address
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}