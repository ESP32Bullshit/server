from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from model import User
from auth_utils import hash_password, verify_password
import requests

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ------------------ Signup ------------------
@app.post("/signup")
def signup(email: str, password: str, public_key: str, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = User(email=email, password=hash_password(password), public_key=public_key)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"user_id": user.id}


# ------------------ Login ------------------
@app.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.password:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect password")

    return {"user_id": user.id}


# ------------------ Google Auth ------------------
@app.post("/google-auth")
def google_auth(google_token: str, public_key: str = None, db: Session = Depends(get_db)):
    resp = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={google_token}")
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid Google token")

    data = resp.json()
    google_id = data["sub"]
    email = data.get("email")

    user = db.query(User).filter(
        (User.google_id == google_id) | (User.email == email)
    ).first()

    if not user:
        user = User(email=email, google_id=google_id, public_key=public_key)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Optional: update the public key if the user provides a new one
        if public_key and not user.public_key:
            user.public_key = public_key
            db.commit()

    return {"user_id": user.id}


@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/server_public_key")
def get_public_key():
    return {"public_key": "your_public_key_here"}

@app.get("/")
def read_root():
    return {"login":"/login", "signup":"/signup", "google_auth":"/google-auth", "health":"/health", "server_public_key":"/server_public_key"}