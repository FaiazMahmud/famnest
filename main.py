from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os
from fastapi.middleware.cors import CORSMiddleware
import random
import string

# Initialize FastAPI app
app = FastAPI()

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set.")

client = AsyncIOMotorClient(MONGO_URI)
db = client['FamNest']

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT configuration
SECRET_KEY = "your_secret_key"  # Replace with a strong secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Helper Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Pydantic Models
class Register(BaseModel):
    name: str
    email: str
    password: str

class Login(BaseModel):
    email: str
    password: str

class GroupCreate(BaseModel):
    email: str
    group_name: str
    group_code: str

class EmailRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str

class UpdatePassword(BaseModel):
    email: str
    new_password: str

class GroupPasswordRequest(BaseModel):
    group_code: str

# Endpoints
@app.post("/register/")
async def register_user(info: Register):
    collection = db.get_collection("Users")
    existing_user = await collection.find_one({"email": info.email})

    if existing_user:
        raise HTTPException(status_code=400, detail="Email is already registered.")

    hashed_password = hash_password(info.password)
    await collection.insert_one({
        "name": info.name,
        "email": info.email,
        "password": hashed_password,
        "groups": [],
        "login_status": False,
        "created_at": datetime.utcnow()
    })
    return {"message": "User registered successfully."}

@app.post("/login/")
async def login_user(info: Login):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user or not verify_password(info.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    await collection.update_one(
        {"email": info.email},
        {"$set": {"login_status": True, "last_login": datetime.utcnow()}}
    )

    access_token = create_access_token({"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout/")
async def logout_user(info: EmailRequest):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    await collection.update_one(
        {"email": info.email},
        {"$set": {"login_status": False}}
    )

    return {"message": "User logged out successfully."}

def serialize_doc(doc):
    # Check if 'created_at' is a datetime object and convert it to ISO format
    if "created_at" in doc and isinstance(doc["created_at"], datetime):
        doc["created_at"] = doc["created_at"].isoformat()  # Convert datetime to ISO format
    return {key: value for key, value in doc.items() if key != "_id"}  # Exclude _id

@app.post("/create-group/")
async def create_group(info: GroupCreate):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")

    # Check if the group code already exists
    existing_group = await group_collection.find_one({"group_code": info.group_code})
    if existing_group:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "message": "Group code already exists."}
        )

    # Create the group data
    group_data = {
        "group_name": info.group_name,
        "group_code": info.group_code,
        "created_at": datetime.utcnow()
    }

    # Insert the group into the Groups collection
    await group_collection.insert_one(group_data)

    # Check if the user exists
    user = await user_collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(
            status_code=404,
            detail={"success": False, "message": "User not found."}
        )

    # Update the user's groups
    await user_collection.update_one(
        {"email": info.email},
        {"$push": {"groups": serialize_doc(group_data)}}  # Serialize and exclude _id
    )

    # Serialize group data for the response
    serialized_group_data = serialize_doc(group_data)

    # Return a successful response
    return {
        "success": True,
        "message": "Group created successfully.",
        "group": serialized_group_data
    }


@app.post("/find-group/")
async def find_group(info: GroupPasswordRequest):
    group_collection = db.get_collection("Groups")
    group = await group_collection.find_one({"group_code": info.group_code})

    if group:
        return {"group_name": group["group_name"], "group_code": group["group_code"]}
    raise HTTPException(status_code=404, detail="Group not found.")

@app.post("/get-user-data/")
async def get_user_data(info: EmailRequest):
    # Access the 'Users' collection
    collection = db.get_collection("Users")
    
    # Fetch the user document by email
    user = await collection.find_one({"email": info.email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Prepare groups data (remove `_id` and other unnecessary fields)
    groups = [
        {
            "group_name": group.get("group_name", "Unknown"),
            "group_code": group.get("group_code", ""),
            "created_at": group.get("created_at").isoformat() if group.get("created_at") else None
        }
        for group in user.get("groups", [])
    ]

    # Return the formatted user data
    return {
        "name": user.get("name"),
        "email": user.get("email"),
        "password": user.get("password"),  # This may not need to be sent to the frontend
        "groups": groups,
        "login_status": user.get("login_status", False),
        "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
        "last_login": user.get("last_login").isoformat() if user.get("last_login") else None,
    }


@app.post("/forgot-password/")
async def forgot_password(info: ResetPasswordRequest):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    reset_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    await collection.update_one(
        {"email": info.email},
        {"$set": {"reset_code": reset_code, "reset_code_expiry": datetime.utcnow() + timedelta(minutes=10)}}
    )

    return {"message": "Password reset code sent.", "reset_code": reset_code}

@app.post("/reset-password/")
async def reset_password(info: UpdatePassword):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    hashed_password = hash_password(info.new_password)
    await collection.update_one(
        {"email": info.email},
        {"$set": {"password": hashed_password}, "$unset": {"reset_code": "", "reset_code_expiry": ""}}
    )

    return {"message": "Password reset successfully."}

@app.get("/all-users/")
async def get_all_users():
    collection = db.get_collection("Users")
    users = await collection.find({}).to_list(length=100)
    return [{"name": user.get("name"), "email": user.get("email"), "login_status": user.get("login_status")} for user in users]
