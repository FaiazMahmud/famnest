from fastapi import FastAPI, HTTPException, Depends, UploadFile, File , Form
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os
from fastapi.middleware.cors import CORSMiddleware

from typing import Optional, List
from bson import ObjectId

import random
import string
import cloudinary
import cloudinary.uploader
import uuid

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

# Cloudinary configuration
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

if not all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]):
    raise RuntimeError("Cloudinary environment variables are not set.")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET,
)

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
    profile_picture_url: str

class Login(BaseModel):
    email: str
    password: str

class GroupCreate(BaseModel):
    email: str
    group_name: str
    group_code: str

class EmailRequest(BaseModel):
    email: str

# Password Reset Models
class ResetPasswordRequest(BaseModel):
    email: str

class UpdatePassword(BaseModel):
    email: str
    reset_code: str
    new_password: str
    
class GroupPasswordRequest(BaseModel):
    group_code: str

class JoinGroupRequest(BaseModel):
    email: str
    group_code: str

class LeaveGroupRequest(BaseModel):
    email: str
    group_code: str

class UpdateCurrentGroup(BaseModel):
    email: str
    group_code: str


class RemoveGroupMemberRequest(BaseModel):
    group_code: str
    email: str

class EditUserProfile(BaseModel):
    new_name: str
    new_email: str
    old_email: str
    profile_picture_url : str

class ChangePassword(BaseModel):
    email: str
    new_password: str


# Pydantic Models
class EventCreate(BaseModel):
    group_code: str
    name: str
    start_date: datetime
    end_date: datetime
    location: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None


class EventRetrieve(BaseModel):
    id: str
    group_code: str
    name: str
    start_date: datetime
    end_date: datetime
    location: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    

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
        "current_group": None,
        "profile_picture_url": None,  # Default to None
        "login_status": False,
        "created_at": datetime.utcnow(),
        "profile_picture_url": info.profile_picture_url
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
    if "created_at" in doc and isinstance(doc["created_at"], datetime):
        doc["created_at"] = doc["created_at"].isoformat()
    return {key: value for key, value in doc.items() if key != "_id"}

@app.post("/create-group/")
async def create_group(info: GroupCreate):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")

    existing_group = await group_collection.find_one({"group_code": info.group_code})
    if existing_group:
        raise HTTPException(status_code=400, detail="Group code already exists.")

    group_data = {
        "group_name": info.group_name,
        "group_code": info.group_code,
        "created_at": datetime.utcnow(),
        "members": [{"email": info.email, "joined_at": datetime.utcnow()}]
    }

    await group_collection.insert_one(group_data)

    user = await user_collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user_groups = user.get("groups", [])
    user_groups.append({"group_name": info.group_name, "group_code": info.group_code, "created_at": datetime.utcnow()})

    current_group = user.get("current_group")
    if not current_group:
        current_group = {"group_name": info.group_name, "group_code": info.group_code}

    await user_collection.update_one(
        {"email": info.email},
        {"$set": {"groups": user_groups, "current_group": current_group}}
    )

    return {
         "success": True,
         "message": "Group created successfully.",
         "group": {
            "group_name": info.group_name,
            "group_code": info.group_code,
            "created_at": datetime.utcnow().isoformat(),
             }
    }

@app.post("/get-user-data/")
async def get_user_data(info: EmailRequest):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    groups = [serialize_doc(group) for group in user.get("groups", [])]

    return {
        "name": user.get("name"),
        "email": user.get("email"),
        "groups": groups,
        "current_group": user.get("current_group"),
        "profile_picture_url": user.get("profile_picture_url"),
        "login_status": user.get("login_status"),
        "created_at": user.get("created_at").isoformat() if isinstance(user.get("created_at"), datetime) else user.get("created_at"),
        "last_login": user.get("last_login").isoformat() if isinstance(user.get("last_login"), datetime) else user.get("last_login"),
    }

@app.post("/join-group/")
async def join_group(info: JoinGroupRequest):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")

    group = await group_collection.find_one({"group_code": info.group_code})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found.")

    for member in group.get("members", []):
        if member["email"] == info.email:
            raise HTTPException(status_code=400, detail="User is already a member of this group.")

    await group_collection.update_one(
        {"group_code": info.group_code},
        {"$push": {"members": {"email": info.email, "joined_at": datetime.utcnow()}}}
    )

    user = await user_collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user_groups = user.get("groups", [])
    user_groups.append({"group_name": group["group_name"], "group_code": group["group_code"], "created_at": group["created_at"]})

    await user_collection.update_one(
        {"email": info.email},
        {"$set": {"groups": user_groups}}
    )

    return {"message": "User successfully joined the group."}

@app.post("/leave-group/")
async def leave_group(info: LeaveGroupRequest):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")

    await group_collection.update_one(
        {"group_code": info.group_code},
        {"$pull": {"members": {"email": info.email}}}
    )

    await user_collection.update_one(
        {"email": info.email},
        {"$pull": {"groups": {"group_code": info.group_code}}}
    )

    return {"message": "User successfully left the group."}


@app.post("/get-group-members/")
async def get_group_members(info: GroupPasswordRequest):
    group_collection = db.get_collection("Groups")
    group = await group_collection.find_one({"group_code": info.group_code})

    if not group:
        raise HTTPException(status_code=404, detail="Group not found.")

    return {"group_name": group["group_name"], "members": group["members"]}


@app.post("/update-current-group/")
async def update_current_group(info: UpdateCurrentGroup):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    group = next((g for g in user.get("groups", []) if g["group_code"] == info.group_code), None)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found for this user.")

    await collection.update_one(
        {"email": info.email},
        {"$set": {"current_group": group}}
    )

    return {"message": "Current group updated successfully."}


@app.post("/find-group/")
async def find_group(info: GroupPasswordRequest):
    group_collection = db.get_collection("Groups")
    group = await group_collection.find_one({"group_code": info.group_code})

    if group:
        return {"group_name": group["group_name"], "group_code": group["group_code"]}
    raise HTTPException(status_code=404, detail="Group not found.")


@app.post("/remove-group-member/")
async def remove_group_member(info: RemoveGroupMemberRequest):
    group_collection = db.get_collection("Groups")
    group = await group_collection.find_one({"group_code": info.group_code})

    if not group:
        raise HTTPException(status_code=404, detail="Group not found.")

    if not any(member["email"] == info.email for member in group["members"]):
        raise HTTPException(status_code=404, detail="Member not found in the group.")

    await group_collection.update_one(
        {"group_code": info.group_code},
        {"$pull": {"members": {"email": info.email}}}
    )

    return {"message": "Member removed successfully."}

# Forgot Password Endpoint
@app.post("/forgot-password/")
async def forgot_password(info: ResetPasswordRequest):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Generate Reset Code
    reset_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    expiry_time = datetime.utcnow() + timedelta(minutes=10)

    await collection.update_one(
        {"email": info.email},
        {"$set": {"reset_code": reset_code, "reset_code_expiry": expiry_time}}
    )
    return {"message": "Password reset code sent.", "reset_code": reset_code}


# Reset Password Endpoint
@app.post("/reset-password/")
async def reset_password(info: UpdatePassword):
    collection = db.get_collection("Users")
    user = await collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Validate Reset Code
    if user.get("reset_code") != info.reset_code:
        raise HTTPException(status_code=400, detail="Invalid reset code.")
    if user.get("reset_code_expiry") < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset code has expired.")

    # Hash the new password
    hashed_password = hash_password(info.new_password)

    # Update Password
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

@app.post("/edit-profile/")
async def edit_user_profile(info: EditUserProfile):
    collection = db.get_collection("Users")
    existing_user = await collection.find_one({"email": info.new_email})
    
    if existing_user and info.new_email != info.old_email:
        raise HTTPException(status_code=400, detail="This Email is Already Taken.")

    # Update the username and email fields
    update_result = collection.update_one(
        {"email": info.old_email},  # Query to find the document
        {
            "$set": {
                "name": info.new_name,
                "email": info.new_email,
                "profile_picture_url": info.profile_picture_url
            }
        }
    )
    return {"message": "Your Profile is Updated Successfully"}

@app.post("/upload-profile-picture/")
async def upload_profile_picture(file: UploadFile = File(...)):
    try:
        # Validate the file type (ensure it's an image)
        if not file.content_type.startswith('image'):
            raise HTTPException(status_code=400, detail="Invalid file type. Please upload an image.")
        
        # Generate a unique name for the file (use UUID or current timestamp)
        file_extension = file.filename.split('.')[-1]
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        
        # Upload the image to Cloudinary
        result = cloudinary.uploader.upload(file.file, folder="profile_pictures", public_id=unique_filename)
        profile_pic_url = result.get("url")
        
        return {
            "message": "Profile picture uploaded successfully.",
            "profile_picture_url": profile_pic_url  # Optionally return the URL
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload image: {str(e)}")

@app.post("/change-password/")
async def change_password(info: ChangePassword):
    hashed_password = hash_password(info.new_password)
    collection = db.get_collection("Users")
    update_result = collection.update_one(
        {"email": info.email},  # Query to find the document
        {
            "$set": {
                "password": hashed_password
            }
        }
    )
    return {"message": "Your Password is Changed Successfully."}






@app.post("/create-event/")
async def create_event(event: EventCreate):
    """
    Create a new event for a specific group.
    """
    event_collection = db.get_collection("Events")
    group_collection = db.get_collection("Groups")

    # Validate group code
    group = await group_collection.find_one({"group_code": event.group_code})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found.")

    # Validate start and end date
    if event.end_date <= event.start_date:
        raise HTTPException(status_code=400, detail="End date must be after start date.")

    # Insert the event
    event_data = {
        "group_code": event.group_code,
        "name": event.name,
        "start_date": event.start_date,
        "end_date": event.end_date,
        "location": event.location,
        "url": event.url,
        "description": event.description,
        "created_at": datetime.utcnow(),
    }
    result = await event_collection.insert_one(event_data)

    return {"success": True, "message": "Event created successfully.", "event_id": str(result.inserted_id)}


@app.get("/get-events/{group_code}", response_model=List[EventRetrieve])
async def get_events(group_code: str, skip: int = 0, limit: int = 20):
    """
    Retrieve all events for a specific group.
    """
    event_collection = db.get_collection("Events")
    events = await event_collection.find({"group_code": group_code}).skip(skip).limit(limit).to_list(length=limit)

    return [
        {
            "id": str(event["_id"]),
            "group_code": event["group_code"],
            "name": event["name"],
            "start_date": event["start_date"],
            "end_date": event["end_date"],
            "location": event.get("location"),
            "url": event.get("url"),
            "description": event.get("description"),
        }
        for event in events
    ]


@app.get("/get-event/{event_id}", response_model=EventRetrieve)
async def get_event(event_id: str):
    """
    Retrieve details of a single event by its ID.
    """
    event_collection = db.get_collection("Events")

    event = await event_collection.find_one({"_id": ObjectId(event_id)})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    return {
        "id": str(event["_id"]),
        "group_code": event["group_code"],
        "name": event["name"],
        "start_date": event["start_date"],
        "end_date": event["end_date"],
        "location": event.get("location"),
        "url": event.get("url"),
        "description": event.get("description"),
    }


@app.delete("/delete-event/{event_id}")
async def delete_event(event_id: str):
    """
    Delete an event by its ID.
    """
    event_collection = db.get_collection("Events")

    result = await event_collection.delete_one({"_id": ObjectId(event_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Event not found.")

    return {"success": True, "message": "Event deleted successfully."}


@app.put("/update-event/{event_id}")
async def update_event(event_id: str, event: EventCreate):
    """
    Update an event by its ID.
    """
    event_collection = db.get_collection("Events")

    updated_event = {
        "group_code": event.group_code,
        "name": event.name,
        "start_date": event.start_date,
        "end_date": event.end_date,
        "location": event.location,
        "url": event.url,
        "description": event.description,
        "updated_at": datetime.utcnow(),
    }

    result = await event_collection.update_one({"_id": ObjectId(event_id)}, {"$set": updated_event})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Event not found.")

    return {"success": True, "message": "Event updated successfully."}

    
