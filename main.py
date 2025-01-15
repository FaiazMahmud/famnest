from fastapi import FastAPI, HTTPException, Depends, UploadFile, File , Form,APIRouter, Body
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
from urllib.parse import urlparse
import cloudinary.api
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

class CategoryCreate(BaseModel):
    category_name: str
    group_code: str


class FolderCreate(BaseModel):
    folder_name: str
    category_id: str
    parent_folder_id: str = None  # Optional parent folder for nested folders

class FileUpload(BaseModel):
    file_name: str
    folder_id: str
    file_url: str

class RenameFolder(BaseModel):
    folder_id: str
    new_name: str

class DeleteFolder(BaseModel):
    folder_id: str



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


'''
@app.post("/create-group/")
async def create_group(info: GroupCreate):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")

    # Check if the group code already exists
    existing_group = await group_collection.find_one({"group_code": info.group_code})
    if existing_group:
        raise HTTPException(status_code=400, detail="Group code already exists.")

    # Insert the group into the Groups collection
    group_data = {
        "group_name": info.group_name,
        "group_code": info.group_code,
        "created_at": datetime.utcnow(),
        "members": [{"email": info.email, "joined_at": datetime.utcnow()}]
    }
    await group_collection.insert_one(group_data)

    # Fetch the user and update their group details
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

    # Create default categories and folders
    default_categories = ["Education", "Finance", "Medical"]
    default_folders = ["Docs", "Images", "Videos", "Music"]

    for category_name in default_categories:
        # Insert category into the Categories collection
        category_data = {
            "category_name": category_name,
            "group_code": info.group_code,
            "is_preset": True
        }
        category_result = await categories_collection.insert_one(category_data)

        # Insert default folders for the category
        for folder_name in default_folders:
            folder_data = {
                "folder_name": folder_name,
                "category_id": str(category_result.inserted_id)
            }
            await folders_collection.insert_one(folder_data)

    return {
        "success": True,
        "message": "Group created successfully with default categories and folders.",
        "group": {
            "group_name": info.group_name,
            "group_code": info.group_code,
            "created_at": datetime.utcnow().isoformat(),
        }
    }'''

@app.post("/create-group/")
async def create_group(info: GroupCreate):
    group_collection = db.get_collection("Groups")
    user_collection = db.get_collection("Users")
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")

    # Check if the group already exists
    existing_group = await group_collection.find_one({"group_code": info.group_code})
    if existing_group:
        raise HTTPException(status_code=400, detail="Group code already exists.")

    # Insert the group
    group_data = {
        "group_name": info.group_name,
        "group_code": info.group_code,
        "created_at": datetime.utcnow(),
        "members": [{"email": info.email, "joined_at": datetime.utcnow()}],
    }
    await group_collection.insert_one(group_data)

    # Update user groups
    user = await user_collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user_groups = user.get("groups", [])
    user_groups.append({"group_name": info.group_name, "group_code": info.group_code})
    await user_collection.update_one({"email": info.email}, {"$set": {"groups": user_groups}})

    # Create default categories and folders
    default_categories = ["Education", "Finance", "Medical"]
    default_folders = ["Docs", "Images", "Videos", "Music"]

    for category_name in default_categories:
        category = {
            "category_name": category_name,
            "group_code": info.group_code,
            "is_preset": True,
        }
        category_result = await categories_collection.insert_one(category)
        for folder_name in default_folders:
            folder = {
                "folder_name": folder_name,
                "category_id": str(category_result.inserted_id),
                "parent_folder_id": None,
                "created_at": datetime.utcnow(),
            }
            await folders_collection.insert_one(folder)

    return {"success": True, "message": "Group created successfully."}



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

    # Check if the group exists
    group = await group_collection.find_one({"group_code": info.group_code})
    if not group:
        raise HTTPException(status_code=404, detail="Group not found.")

    # Check if the user is already a member
    if any(member["email"] == info.email for member in group.get("members", [])):
        raise HTTPException(status_code=400, detail="User is already a member of this group.")

    # Add the user to the group
    await group_collection.update_one(
        {"group_code": info.group_code},
        {"$push": {"members": {"email": info.email, "joined_at": datetime.utcnow()}}}
    )

    # Check if the user exists
    user = await user_collection.find_one({"email": info.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Update user's groups and current group
    user_groups = user.get("groups", [])
    group_data = {
        "group_name": group["group_name"],
        "group_code": group["group_code"],
        "created_at": group["created_at"]
    }
    user_groups.append(group_data)

    current_group = group_data  # Set the current group to the newly joined group

    await user_collection.update_one(
        {"email": info.email},
        {"$set": {"groups": user_groups, "current_group": current_group}}
    )

    # Return success response
    return {
        "success": True,
        "message": "User successfully joined the group.",
        "group": {
            "group_name": group["group_name"],
            "group_code": group["group_code"],
            "created_at": group["created_at"]
        }
    }



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

# @app.post("/upload-image/")
# async def upload_image(
#     file_name: str = Form(...), 
#     group_code: str = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         # Upload the file to Cloudinary first
#         upload_result = cloudinary.uploader.upload(
#             file.file,
#             public_id=file_name,
#             resource_type="image",  # Adjust resource_type if needed
#         )

#         # Extract the Cloudinary URL
#         cloudinary_url = upload_result.get("secure_url")
#         if not cloudinary_url:
#             raise HTTPException(status_code=500, detail="Failed to upload image to Cloudinary")

#         # Check if group exists in the database
#         groups_collection = db.get_collection("TimeCapsuleImages")
#         user = await groups_collection.find_one({"group_code": group_code})  # Use await here

#         if user:
#             # If group exists, push the file details to the existing document
#             result = await groups_collection.update_one(  # Use await here
#                 {"group_code": group_code},
#                 {
#                     "$push": {
#                         "uploaded_images": {
#                             "file_name": file_name,
#                             "image_url": cloudinary_url
#                         }
#                     }
#                 }
#             )
#             if result.modified_count == 0:
#                 raise HTTPException(status_code=500, detail="Failed to update group with file details")
#             print("File added to existing user.")
#         else:
#             # If group does not exist, create a new user and add the file details
#             new_user = {
#                 "group_code": group_code,  # Assuming you are adding an email
#                 "uploaded_images": [
#                     {
#                         "file_name": file_name,
#                         "image_url": cloudinary_url
#                     }
#                 ]
#             }
#             await groups_collection.insert_one(new_user)  # Use await here
#             print("New user created and file details added.")

#         # Return the response directly as a dictionary
#         return {"message": "File uploaded successfully", "image_url": cloudinary_url}

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.post("/upload-image/")
# async def upload_image(
#     file_name: str = Form(...), 
#     group_code: str = Form(...),
#     file: UploadFile = File(...),
# ):
#     try:
#         # Upload the file to Cloudinary first
#         upload_result = cloudinary.uploader.upload(
#             file.file,
#             public_id=f'TimeCapsuleImages/{file_name}',
#             resource_type="image",  # Adjust resource_type if needed
#         )

#         # Extract the Cloudinary URL
#         cloudinary_url = upload_result.get("secure_url")
#         if not cloudinary_url:
#             raise HTTPException(status_code=500, detail="Failed to upload image to Cloudinary")

#         # Check if group exists in the database
#         groups_collection = db.get_collection("TimeCapsuleImages")
#         user = await groups_collection.find_one({"group_code": group_code})  # Use await here

#         if user:
#             # If group exists, push the file details to the existing document
#             result = await groups_collection.update_one(  # Use await here
#                 {"group_code": group_code},
#                 {
#                     "$push": {
#                         "uploaded_images": {
#                             "file_name": file_name,
#                             "image_url": cloudinary_url
#                         }
#                     }
#                 }
#             )
#             if result.modified_count == 0:
#                 raise HTTPException(status_code=500, detail="Failed to update group with file details")
#             print("File added to existing user.")
#         else:
#             # If group does not exist, create a new user and add the file details
#             new_user = {
#                 "group_code": group_code,  # Assuming you are adding an email
#                 "uploaded_images": [
#                     {
#                         "file_name": file_name,
#                         "image_url": cloudinary_url
#                     }
#                 ]
#             }
#             await groups_collection.insert_one(new_user)  # Use await here
#             print("New user created and file details added.")

#         # Return the response directly as a dictionary
#         return {"message": "File uploaded successfully", "image_url": cloudinary_url}

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
@app.post("/upload-mediafiles/")
async def upload_media(
    file_name: str = Form(...),
    group_code: str = Form(...),
    file: UploadFile = File(...),
    resource_type: str = Form(...),
):
    try:
        # Upload the file to Cloudinary
        upload_result = cloudinary.uploader.upload(
            file.file,
            public_id=f'TimeCapsuleMedia/{file_name}',
            resource_type=resource_type,
        )

        # Extract the Cloudinary URL
        cloudinary_url = upload_result.get("secure_url")
        if not cloudinary_url:
            raise HTTPException(status_code=500, detail="Failed to upload media to Cloudinary")

        # Check if group exists in the database
        groups_collection = db.get_collection("TimeCapsuleMediaFiles")
        user = await groups_collection.find_one({"group_code": group_code})  # Use await here

        if user:
            # If group exists, push the file details to the existing document
            result = await groups_collection.update_one(  # Use await here
                {"group_code": group_code},
                {
                    "$push": {
                        f"uploaded_{resource_type}s": {
                            "file_name": file_name,
                            f"url": cloudinary_url
                        }
                    }
                }
            )
            if result.modified_count == 0:
                raise HTTPException(status_code=500, detail=f"Failed to update group with {resource_type} details")
            print(f"{resource_type.capitalize()} added to existing user.")
        else:
            # If group does not exist, create a new user and add the file details
            new_user = {
                "group_code": group_code,
                f"uploaded_{resource_type}s": [
                    {
                        "file_name": file_name,
                        f"url": cloudinary_url
                    }
                ]
            }
            await groups_collection.insert_one(new_user)  # Use await here
            print(f"New user created and {resource_type} details added.")

        # Return the response directly as a dictionary
        return {"message": "File uploaded successfully", f"url": cloudinary_url}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# @app.get("/get-images/")
# async def get_images(group_code: str):
#     print(group_code)
#     try:
#         # Fetch images associated with the group from MongoDB
#         groups_collection = db.get_collection("TimeCapsule")
#         group = await groups_collection.find_one({"group_code": group_code})
        
#         # If the group is not found, return an empty list
#         if not group:
#             print(group_code)
#             return {"images": []}
        
#         # Return the list of images with their URLs
#         images = group.get("uploaded_images", [])
#         return {"images": images}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.get("/get-mediafiles/")
async def get_mediafiles(group_code: str, media_type: str):
    try:
        # Fetch the media files associated with the group from MongoDB
        groups_collection = db.get_collection("TimeCapsuleMediaFiles")
        group = await groups_collection.find_one({"group_code": group_code})
        
        # If the group is not found, return an empty list
        if not group:
            return {f"{media_type}s": []}
        print("i am here");
        print(group_code);
        # Determine which type of media to return (either images or videos)
        if media_type == "image":
            media_files = group.get("uploaded_images", [])
        elif media_type == "video":
            media_files = group.get("uploaded_videos", [])
        else:
            raise HTTPException(status_code=400, detail="Invalid media type. Use 'image' or 'video'.")
        return {f"{media_type}s": media_files}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def extract_public_id(url: str) -> str:
    # Parse the URL to extract the public ID
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.split("/")

    # Find where "upload" appears in the path and get the index of the next part
    if "upload" in path_parts:
        # Skip version (v<version_number>) and start from folder name
        upload_index = path_parts.index("upload") + 1
        public_id_parts = path_parts[upload_index + 1:]  # Skip version part and get everything after "upload"

        # Join the parts together to form the public ID
        public_id_with_extension = "/".join(public_id_parts)

        # Remove the file extension (e.g., .jpeg.jpg) from the public ID
        public_id = ".".join(public_id_with_extension.split(".")[:-1])

        return public_id
    raise ValueError("Invalid Cloudinary URL")
    
# @app.delete("/delete-image/{group_code}/{index}")
# async def delete_image(group_code: str, index: int):
#     collection = db.get_collection("TimeCapsuleImages")
#     document = await collection.find_one({"group_code": group_code})
#     if not document:
#         raise HTTPException(status_code=404, detail="Group not found")
#     print("noooh")
#     print(group_code)
#     # Check if index is valid
#     uploaded_images = document.get("uploaded_images", [])
#     if index < 0 or index >= len(uploaded_images):
#         raise HTTPException(status_code=400, detail="Invalid index")

#     image_url = uploaded_images[index].get("image_url")
#     # Remove the item at the specified index
#     uploaded_images.pop(index)
#     if not image_url:
#         raise HTTPException(status_code=404, detail="Image URL not found")
#     public_id = extract_public_id(image_url)
#     #print(public_id)
#     response = cloudinary.api.delete_resources([public_id])
#     # Update the document in MongoDB
#     result = await collection.update_one(
#         {"group_code": group_code},
#         {"$set": {"uploaded_images": uploaded_images}}
#     )
#     if result.modified_count == 1:
#         return {"message": "Image deleted successfully"}
#     else:
#         raise HTTPException(status_code=500, detail="Failed to update document")

# @app.put("/rename-image/{group_code}/{index}/{new_name}/{media_type}")
# async def rename_image(group_code: str, index: int, new_name: str , media_type : str):
#     collection = db.get_collection("TimeCapsuleMediaFiles")
#     # Find the document to ensure it exists
#     document = await collection.find_one({"group_code": group_code})
#     if not document:
#         raise HTTPException(status_code=404, detail="Group not found")
#     # Check if the index is valid
#     if index < 0 or index >= len(document.get("uploaded_images", [])):
#         raise HTTPException(status_code=400, detail="Invalid index")
#     # Use MongoDB positional array updates to change the file_name
#     result = await collection.update_one(
#         {"group_code": group_code},
#         {"$set": {f"uploaded_images.{index}.file_name": new_name}}
#     )
#     if result.modified_count == 1:
#         return {"message": "File name updated successfully"}
#     else:
#         raise HTTPException(status_code=500, detail="Failed to update document")

@app.put("/rename-mediafiles/{group_code}/{index}/{new_name}/{media_type}")
async def rename_media(group_code: str, index: int, new_name: str, media_type: str):
    # Ensure media_type is either 'image' or 'video'
    if media_type not in ["image", "video"]:
        raise HTTPException(status_code=400, detail="Invalid media type. Use 'image' or 'video'.")

    collection = db.get_collection("TimeCapsuleMediaFiles")
    
    # Find the document to ensure it exists
    document = await collection.find_one({"group_code": group_code})
    if not document:
        raise HTTPException(status_code=404, detail="Group not found")
    
    media_field = f"uploaded_{media_type}s"  # Either 'uploaded_images' or 'uploaded_videos'
    
    # Check if the index is valid for the chosen media type
    if index < 0 or index >= len(document.get(media_field, [])):
        raise HTTPException(status_code=400, detail="Invalid index")
    
    result = await collection.update_one(
        {"group_code": group_code},
        {"$set": {f"{media_field}.{index}.file_name": new_name}}
    )
    
    if result.modified_count == 1:
        return {"message": "File name updated successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to update document")

@app.delete("/delete-mediafiles/{group_code}/{index}/{media_type}")
async def delete_media(group_code: str, index: int, media_type: str):
    # Ensure media_type is either 'image' or 'video'
    if media_type not in ["image", "video"]:
        raise HTTPException(status_code=400, detail="Invalid media type. Use 'image' or 'video'.")

    # Define the correct collection and media field
    collection = db.get_collection("TimeCapsuleMediaFiles")
    media_field = f"uploaded_{media_type}s"  # Either 'uploaded_images' or 'uploaded_videos'
    
    # Find the document to ensure it exists
    document = await collection.find_one({"group_code": group_code})
    if not document:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if the index is valid for the selected media type
    uploaded_media = document.get(media_field, [])
    if index < 0 or index >= len(uploaded_media):
        raise HTTPException(status_code=400, detail="Invalid index")
    
    media_url = uploaded_media[index].get("url")
    if not media_url:
        raise HTTPException(status_code=404, detail="Media URL not found")
    
    public_id = extract_public_id(media_url)

    # Remove the media item from the list
    uploaded_media.pop(index)
    
    if public_id:
        response = cloudinary.api.delete_resources([public_id])
    
    # Update the document in MongoDB
    result = await collection.update_one(
        {"group_code": group_code},
        {"$set": {media_field: uploaded_media}}
    )
    
    if result.modified_count == 1:
        return {"message": f"{media_type.capitalize()} deleted successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to update document")


'''
@app.post("/categories/")
async def create_category(info: CategoryCreate):
    """
    Add a user-created category to a group.
    """
    categories_collection = db.get_collection("Categories")
    category_data = {
        "category_name": info.category_name,
        "group_code": info.group_code,
        "is_preset": False  # User-created category
    }
    result = await categories_collection.insert_one(category_data)
    return {
        "success": True,
        "message": "Category created successfully.",
        "category_id": str(result.inserted_id)
    }
'''
@app.post("/categories/")
async def create_category(info: CategoryCreate):
    """
    Add a user-created category to a group and create default folders.
    """
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")

    # Create the category
    category_data = {
        "category_name": info.category_name,
        "group_code": info.group_code,
        "is_preset": False  # User-created category
    }
    category_result = await categories_collection.insert_one(category_data)

    # Create default folders for the new category
    default_folders = ["Docs", "Images", "Videos", "Music"]
    for folder_name in default_folders:
        folder_data = {
            "folder_name": folder_name,
            "category_id": str(category_result.inserted_id),
            "parent_folder_id": None ,
            "created_at": datetime.utcnow(),# Default folders have no parent
        }
        await folders_collection.insert_one(folder_data)

    return {
        "success": True,
        "message": "Category created successfully with default folders.",
        "category_id": str(category_result.inserted_id)
    }


@app.get("/categories/")
async def get_categories(group_code: str):
    """
    Fetch categories for a specific group.
    Includes both preset and user-created categories.
    """
    try:
        categories_cursor = db["Categories"].find({"group_code": group_code})
        categories = await categories_cursor.to_list(length=100)
        return [{
            "id": str(category["_id"]),
            "category_name": category["category_name"],
            "is_preset": category.get("is_preset", False)
        } for category in categories]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch categories: {str(e)}")


'''
# Create a category with default folders
@app.post("/categories/")
async def create_category(info: CategoryCreate):
    categories_collection = db["Categories"]
    folders_collection = db["Folders"]

    # Create the category
    category_data = {
        "category_name": info.category_name,
        "group_code": info.group_code,
        "is_preset": False
    }
    category_result = await categories_collection.insert_one(category_data)

    # Create default folders for the category
    default_folders = ["Docs", "Images", "Videos", "Music"]
    for folder_name in default_folders:
        folder_data = {
            "folder_name": folder_name,
            "category_id": str(category_result.inserted_id),
            "parent_folder_id": None,
            "created_at": datetime.utcnow()
        }
        await folders_collection.insert_one(folder_data)

    return {
        "success": True,
        "message": "Category created successfully with default folders.",
        "category_id": str(category_result.inserted_id)
    }

# Fetch all categories for a specific group
@app.get("/categories/")
async def get_categories(group_code: str):
    try:
        categories_cursor = db["Categories"].find({"group_code": group_code})
        categories = await categories_cursor.to_list(length=100)
        return [
            {
                "id": str(category["_id"]),
                "category_name": category["category_name"],
                "is_preset": category.get("is_preset", False)
            } for category in categories
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch categories: {str(e)}")
'''

#rename the category

from fastapi import HTTPException, APIRouter, Body

@app.put("/categories/{category_id}")
async def rename_category(category_id: str, body: dict = Body(...)):
    """
    Rename a category by ID and group code.
    """
    group_code = body.get("group_code")
    new_name = body.get("new_name")

    if not group_code or not new_name:
        raise HTTPException(status_code=400, detail="group_code and new_name are required.")

    categories_collection = db.get_collection("Categories")

    # Find and update the category
    update_result = await categories_collection.update_one(
        {"_id": ObjectId(category_id), "group_code": group_code},
        {"$set": {"category_name": new_name}}
    )

    if update_result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Category not found or group mismatch.")

    return {"success": True, "message": "Category renamed successfully."}


@app.delete("/categories/{category_id}")
async def delete_category(category_id: str, body: dict = Body(...)):
    """
    Delete a category by ID and group code.
    """
    group_code = body.get("group_code")

    if not group_code:
        raise HTTPException(status_code=400, detail="group_code is required.")

    categories_collection = db.get_collection("Categories")

    # Validate and delete the category
    delete_result = await categories_collection.delete_one(
        {"_id": ObjectId(category_id), "group_code": group_code}
    )

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Category not found or group mismatch.")

    return {"success": True, "message": "Category deleted successfully."}


@app.post("/create-folder/")
async def create_folder(folder_info: FolderCreate):
    folders_collection = db.get_collection("Folders")

    folder_data = {
        "folder_name": folder_info.folder_name,
        "category_id": folder_info.category_id,
        "parent_folder_id": folder_info.parent_folder_id,
        "created_at": datetime.utcnow(),
    }
    result = await folders_collection.insert_one(folder_data)
    return {"success": True, "folder_id": str(result.inserted_id)}


@app.get("/folders/{category_id}/")
async def get_folders(category_id: str, parent_folder_id: str = None):
    folders_collection = db.get_collection("Folders")
    query = {"category_id": category_id, "parent_folder_id": parent_folder_id}
    folders = await folders_collection.find(query).to_list(None)
    return [{"id": str(folder["_id"]), "folder_name": folder["folder_name"]} for folder in folders]

'''
# Fetch folders for a specific category
@app.get("/folders/")
async def get_folders(category_id: str, parent_folder_id: str = None):
    try:
        query = {"category_id": category_id}
        if parent_folder_id is not None:
            query["parent_folder_id"] = parent_folder_id

        folders_cursor = db["Folders"].find(query)
        folders = await folders_cursor.to_list(length=100)
        return [
            {
                "id": str(folder["_id"]),
                "folder_name": folder["folder_name"],
                "parent_folder_id": folder.get("parent_folder_id"),
                "created_at": folder["created_at"]
            } for folder in folders
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch folders: {str(e)}")

# Create a folder
@app.post("/folders/")
async def create_folder(info: FolderCreate):
    folders_collection = db["Folders"]

    folder_data = {
        "folder_name": info.folder_name,
        "category_id": info.category_id,
        "parent_folder_id": info.parent_folder_id,
        "created_at": datetime.utcnow()
    }
    folder_result = await folders_collection.insert_one(folder_data)

    return {
        "success": True,
        "message": "Folder created successfully.",
        "folder_id": str(folder_result.inserted_id)
    }



@app.put("/rename-folder/")
async def rename_folder(rename_info: RenameFolder):
    folders_collection = db.get_collection("Folders")

    result = await folders_collection.update_one(
        {"_id": ObjectId(rename_info.folder_id)},
        {"$set": {"folder_name": rename_info.new_name}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Folder not found.")
    return {"success": True, "message": "Folder renamed successfully."}

@app.delete("/delete-folder/")
async def delete_folder(delete_info: DeleteFolder):
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    folder_id = delete_info.folder_id

    # Check for subfolders or files
    subfolders = await folders_collection.find({"parent_folder_id": folder_id}).to_list(None)
    files = await files_collection.find({"folder_id": folder_id}).to_list(None)
    if subfolders or files:
        raise HTTPException(status_code=400, detail="Folder contains subfolders or files.")

    result = await folders_collection.delete_one({"_id": ObjectId(folder_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Folder not found.")
    return {"success": True, "message": "Folder deleted successfully."}
