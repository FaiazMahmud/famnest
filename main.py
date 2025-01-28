from fastapi import FastAPI, HTTPException, Depends, UploadFile, File , Form,APIRouter, Body, Query
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os
from fastapi.middleware.cors import CORSMiddleware
from magic import from_buffer
from typing import Optional, List
from bson import ObjectId



from pymongo import MongoClient


import mimetypes
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
budget_collection = db['budget']
expense_collection = db['expense']


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

# Pydantic Models
class CategoryCreate(BaseModel):
    group_code: str
    category_name: str

class RenameCategory(BaseModel):
    group_code: str
    new_name: str

class CategoryResponse(BaseModel):
    id: str
    category_name: str
    is_preset: bool
    created_at: Optional[str] = None

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

# Base Model for File Upload
class FileUploadModel(BaseModel):
    category_id: str
    folder_id: str
    file_name: str
    cloudinary_url: str
    public_id: str
    file_type: str
    created_at: datetime

#Base Model for expense_tracking 
class Budget(BaseModel):
    category: str
    month: datetime
    amount: float
    spent: float = 0.0
    groupCode: str

class Expense(BaseModel):
    category: str
    date: datetime
    amount: float
    groupCode: str


# # Base Model for expense tracking
# class Budget(BaseModel):
#     id: str  # Store MongoDB ObjectId as a string
#     category: str
#     month: datetime
#     amount: float
#     spent: float = 0.0
#     groupCode: str

# class Expense(BaseModel):
#     id: str  # Store MongoDB ObjectId as a string
#     category: str
#     date: datetime
#     amount: float
#     groupCode: str


# class Budget(BaseModel):
#     group_code: str = Field(..., description="The unique code for the group")
#     category: str = Field(..., description="The category of the budget")
#     month: str = Field(..., description="The month for the budget in YYYY-MM format")
#     amount: float = Field(..., description="The total amount allocated for the budget")
#     spent: float = Field(0, description="The total amount spent from the budget")

# class Expense(BaseModel):
#     group_code: str = Field(..., description="The unique code for the group")
#     category: str = Field(..., description="The category of the expense")
#     date: str = Field(..., description="The date of the expense in YYYY-MM-DD format")
#     amount: float = Field(..., description="The amount spent in this expense")

# Pydantic models for request/response validation
# class Budget(BaseModel):
#     id: Optional[str] = None
#     category: str
#     month: datetime
#     amount: float
#     spent: float = 0.0
#     groupCode: str

# class Expense(BaseModel):
#     id: Optional[str] = None
#     category: str
#     date: datetime
#     amount: float
#     groupCode: str

# # Helper function to convert MongoDB document to Pydantic model
# def budget_from_mongo(budget: dict) -> Budget:
#     budget["id"] = str(budget["_id"])
#     return Budget(**budget)

# def expense_from_mongo(expense: dict) -> Expense:
#     expense["id"] = str(expense["_id"])
#     return Expense(**expense)

# # Endpoint to upload a budget
# @app.post("/budget", response_model=Budget)
# async def upload_budget(budget: Budget):
#     budget_dict = budget.dict()
#     budget_dict.pop("id", None)  # Remove the id field if it exists
#     result = budget_collection.insert_one(budget_dict)
#     if result.inserted_id:
#         budget_dict["id"] = str(result.inserted_id)
#         return budget_dict
#     raise HTTPException(status_code=500, detail="Failed to upload budget")

# # Endpoint to fetch budgets by group code
# @app.get("/get-budgets/{groupCode}", response_model=List[Budget])
# async def fetch_budgets(groupCode: str):
#     budgets = budget_collection.find({"groupCode": groupCode})
#     return [budget_from_mongo(budget) for budget in budgets]

# # Endpoint to upload an expense
# @app.post("/expense", response_model=Expense)
# async def upload_expense(expense: Expense):
#     expense_dict = expense.dict()
#     expense_dict.pop("id", None)  # Remove the id field if it exists
#     result = expense_collection.insert_one(expense_dict)
#     if result.inserted_id:
#         expense_dict["id"] = str(result.inserted_id)
#         return expense_dict
#     raise HTTPException(status_code=500, detail="Failed to upload expense")

# # Endpoint to fetch expenses by group code
# @app.get("/expense", response_model=List[Expense])
# async def fetch_expenses(groupCode: str):
#     expenses = expense_collection.find({"groupCode": groupCode})
#     return [expense_from_mongo(expense) for expense in expenses]





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
#previous correct create group function
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
    }
'''
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

    return {
        "success": True,
        "message": "Group created successfully with default categories and folders.",
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



# Fetch all budgets for a given group code
# @app.get("/get-budgets/{group_code}", response_model=List[Budget])
# async def fetch_budgets(group_code: str):
#     group_budgets = [b for b in budgets if b.group_code == group_code]
#     if not group_budgets:
#         raise HTTPException(status_code=404, detail="No budgets found for the given group code")
#     return group_budgets

# # Fetch all expenses for a given group code
# @app.get("/get-expenses/{group_code}", response_model=List[Expense])
# async def fetch_expenses(group_code: str):
#     group_expenses = [e for e in expenses if e.group_code == group_code]
#     if not group_expenses:
#         raise HTTPException(status_code=404, detail="No expenses found for the given group code")
#     return group_expenses



@app.post("/budget")
async def upload_budget(budget: Budget):
    """
    Uploads a new budget to MongoDB.
    """
    budget_dict = budget.dict(exclude={"id"})  # Exclude 'id' to let MongoDB generate an ObjectId
    result = await budget_collection.insert_one(budget_dict)
    if result.inserted_id:
        # Retrieve the generated ObjectId and set it as a string in the response
        return {"message": "Budget uploaded successfully.", "id": str(result.inserted_id)}
    raise HTTPException(status_code=500, detail="Failed to upload budget.")


@app.post("/expense")
async def upload_expense(expense: Expense):
    """
    Uploads a new expense to MongoDB and updates the corresponding budget's 'spent' field.
    """
    expense_dict = expense.dict(exclude={"id"})  # Exclude 'id' to let MongoDB generate an ObjectId
    result = await expense_collection.insert_one(expense_dict)
    if result.inserted_id:
        # Update the corresponding budget's 'spent' field
        update_result = await budget_collection.update_one(
            {
                "category": expense.category,
                "month": {
                    "$gte": datetime(expense.date.year, expense.date.month, 1),
                    "$lt": datetime(expense.date.year, expense.date.month + 1, 1),
                },
                "groupCode": expense.groupCode,
            },
            {"$inc": {"spent": expense.amount}},
        )
        if update_result.modified_count > 0:
            return {"message": "Expense uploaded successfully and budget updated.", "id": str(result.inserted_id)}
        return {"message": "Expense uploaded successfully, but no matching budget was updated.", "id": str(result.inserted_id)}
    raise HTTPException(status_code=500, detail="Failed to upload expense.")


# @app.get("/budget", response_model=List[Budget])
# async def fetch_budgets(groupCode: str):
#     """
#     Fetches all budgets for the specified group code from MongoDB.
#     """
#     try:
#         # Query budgets based on the groupCode
#         budgets = await budget_collection.find({"groupCode": groupCode}).to_list(length=None)
        
#         if not budgets:
#             raise HTTPException(status_code=404, detail="No budgets found for the group code.")

#         # Process each budget and convert ObjectId to string
#         processed_budgets = []
#         for budget in budgets:
#             budget["id"] = str(budget["_id"])
#             del budget["_id"]
#             processed_budgets.append(budget)
        
#         return processed_budgets

#     except Exception as e:
#         print(f"Error fetching budgets: {e}")  # Log the error
#         raise HTTPException(status_code=500, detail="An error occurred while fetching budgets.")
# '''
# @app.get("/get-budgets/{group_code}", response_model=List[BudgetRetrieve])
# async def get_budgets(group_code: str, skip: int = 0, limit: int = 20):
#     """
#     Retrieve all budgets for a specific group.
#     """
#     budget_collection = db.get_collection("Budgets")
#     budgets = await budget_collection.find({"groupCode": group_code}).skip(skip).limit(limit).to_list(length=limit)

#     return [
#         {
#             "id": str(budget["_id"]),
#             "groupCode": budget["groupCode"],
#             "category": budget["category"],
#             "month": budget["month"],
#             "amount": budget["amount"],
#             "spent": budget.get("spent", 0.0),
#         }
#         for budget in budgets
#     ]


# 



# FastAPI code
from urllib.parse import unquote_plus

@app.get("/budget", response_model=List[Budget])
async def fetch_budgets(groupCode: str):
    """Fetches all budgets for the specified group code from MongoDB."""
    try:
        # Decode the URL-encoded groupCode
        decoded_group_code = unquote_plus(unquote_plus(groupCode))
        print(f"Decoded groupCode: {decoded_group_code}")
        
        # Use exact match query with decoded group code
        budgets = await budget_collection.find(
            {"groupCode": decoded_group_code}
        ).to_list(length=None)
        
        if not budgets:
            raise HTTPException(
                status_code=404,
                detail=f"No budgets found for group code: {decoded_group_code}"
            )
        
        processed_budgets = []
        for budget in budgets:
            processed_budget = {
                "id": str(budget["_id"]),
                **{k: v for k, v in budget.items() if k != "_id"}
            }
            processed_budgets.append(processed_budget)
        
        return processed_budgets
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in fetch_budgets: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while fetching budgets: {str(e)}"
        )
# @app.get("/budget", response_model=List[Budget]) 
# async def fetch_budgets(groupCode: str):
#     """Fetches all budgets for the specified group code from MongoDB."""
#     try:
#         # Add logging to debug the incoming groupCode
#         print(f"Attempting to fetch budgets for groupCode: {groupCode}")
        
#         # Escape special characters or validate groupCode if needed
#         # Using raw query to avoid operator interpretation
#         budgets = await budget_collection.find(
#             {"groupCode": {"$eq": groupCode}}
#         ).to_list(length=None)
        
#         # Add debug logging
#         print(f"Query results: {budgets}")
        
#         if not budgets:
#             raise HTTPException(
#                 status_code=404, 
#                 detail=f"No budgets found for group code: {groupCode}"
#             )
            
#         processed_budgets = []
#         for budget in budgets:
#             budget["id"] = str(budget["_id"])
#             del budget["_id"]
#             processed_budgets.append(budget)
            
#         return processed_budgets
        
#     except Exception as e:
#         # Improve error logging
#         print(f"Detailed error while fetching budgets: {str(e)}")
#         raise HTTPException(
#             status_code=500,
#             detail=f"An error occurred while fetching budgets: {str(e)}"
#         )


from urllib.parse import unquote_plus

@app.get("/expense", response_model=List[Expense])
async def fetch_expenses(groupCode: str):
    """
    Fetches all expenses for the specified group code from MongoDB.
    """
    try:
        # Decode the URL-encoded groupCode
        decoded_group_code = unquote_plus(unquote_plus(groupCode))
        print(f"Decoded groupCode for expenses: {decoded_group_code}")
        
        # Use exact match query with decoded group code
        expenses = await expense_collection.find(
            {"groupCode": decoded_group_code}
        ).to_list(length=None)
        
        print(f"Query results: {expenses}")
        
        if not expenses:
            raise HTTPException(
                status_code=404,
                detail=f"No expenses found for group code: {decoded_group_code}"
            )
        
        processed_expenses = []
        for expense in expenses:
            processed_expense = {
                "id": str(expense["_id"]),
                **{k: v for k, v in expense.items() if k != "_id"}
            }
            processed_expenses.append(processed_expense)
        
        return processed_expenses
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Detailed error in fetch_expenses: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while fetching expenses: {str(e)}"
        )

# @app.get("/expense", response_model=List[Expense])
# async def fetch_expenses(groupCode: str):
#     """
#     Fetches all expenses for the specified group code from MongoDB.
#     """
#     try:
#         # Retrieve expenses for the specified group code
#         expenses = await expense_collection.find({"groupCode": groupCode}).to_list(length=None)
        
#         if not expenses:
#             raise HTTPException(status_code=404, detail="No expenses found for the group code.")

#         # Process each expense and convert ObjectId to string
#         processed_expenses = []
#         for expense in expenses:
#             expense["id"] = str(expense["_id"])
#             del expense["_id"]
#             processed_expenses.append(expense)
        
#         return processed_expenses

#     except Exception as e:
#         # Log the exception and return a 500 error with the details
#         print(f"Error fetching expenses: {e}")
#         raise HTTPException(status_code=500, detail="An error occurred while fetching expenses.")



# @app.post("/budget")
# async def upload_budget(budget: Budget):
#     """
#     Uploads a new budget to MongoDB.
#     """
#     budget_dict = budget.dict()
#     result = await budget_collection.insert_one(budget_dict)
#     if result.inserted_id:
#         return {"message": "Budget uploaded successfully.", "id": str(result.inserted_id)}
#     raise HTTPException(status_code=500, detail="Failed to upload budget.")

# @app.post("/expense")
# async def upload_expense(expense: Expense):
#     """
#     Uploads a new expense to MongoDB and updates the corresponding budget's 'spent' field.
#     """
#     expense_dict = expense.dict()
#     result = await expense_collection.insert_one(expense_dict)
#     if result.inserted_id:
#         # Update the corresponding budget
#         update_result = await budget_collection.update_one(
#             {
#                 "category": expense.category,
#                 "month": {"$gte": datetime(expense.date.year, expense.date.month, 1),
#                           "$lt": datetime(expense.date.year, expense.date.month + 1, 1)},
#                 "groupCode": expense.groupCode
#             },
#             {"$inc": {"spent": expense.amount}}
#         )
#         if update_result.modified_count > 0:
#             return {"message": "Expense uploaded successfully and budget updated."}
#         return {"message": "Expense uploaded successfully, but no matching budget was updated."}
#     raise HTTPException(status_code=500, detail="Failed to upload expense.")

# @app.get("/budget", response_model=List[Budget])
# async def fetch_budgets(groupCode: str):
#     """
#     Fetches all budgets for the specified group code from MongoDB.
#     """
#     budgets = await budget_collection.find({"groupCode": groupCode}).to_list(length=None)
#     if budgets:
#         return budgets
#     raise HTTPException(status_code=404, detail="No budgets found for the group code.")

# @app.get("/expense", response_model=List[Expense])
# async def fetch_expenses(groupCode: str):
#     """
#     Fetches all expenses for the specified group code from MongoDB.
#     """
#     expenses = await expense_collection.find({"groupCode": groupCode}).to_list(length=None)
#     if expenses:
#         return expenses
#     raise HTTPException(status_code=404, detail="No expenses found for the group code.")

# def get_budgets_by_group(group_code: str):
#     return [budget for budget in budgets_db if budget.get("groupCode") == group_code]

# def get_expenses_by_group(group_code: str):
#     return [expense for expense in expenses_db if expense.get("groupCode") == group_code]

# # Endpoints
# @app.post("/budget")
# async def upload_budget(budget: Budget, groupCode: str = Query(...)):
#     """
#     Uploads a new budget.
#     """
#     budget_data = budget.dict()
#     budget_data["groupCode"] = groupCode
#     budgets_db.append(budget_data)
#     return {"message": "Budget uploaded successfully."}

# @app.post("/expense")
# async def upload_expense(expense: Expense, groupCode: str = Query(...)):
#     """
#     Uploads a new expense and updates the corresponding budget.
#     """
#     expense_data = expense.dict()
#     expense_data["groupCode"] = groupCode
#     expenses_db.append(expense_data)

#     # Update spent amount in the corresponding budget
#     for budget in budgets_db:
#         if (
#             budget["category"] == expense.category and
#             budget["month"].month == expense.date.month and
#             budget["month"].year == expense.date.year and
#             budget["groupCode"] == groupCode
#         ):
#             budget["spent"] += expense.amount
#             break

#     return {"message": "Expense uploaded successfully."}

# @app.get("/budget", response_model=List[Budget])
# async def fetch_budgets(groupCode: str):
#     """
#     Fetches all budgets for the specified group code.
#     """
#     group_budgets = get_budgets_by_group(groupCode)
#     if not group_budgets:
#         raise HTTPException(status_code=404, detail="No budgets found for the group code.")
#     return group_budgets

# @app.get("/expense", response_model=List[Expense])
# async def fetch_expenses(groupCode: str):
#     """
#     Fetches all expenses for the specified group code.
#     """
#     group_expenses = get_expenses_by_group(groupCode)
#     if not group_expenses:
#         raise HTTPException(status_code=404, detail="No expenses found for the group code.")
#     return group_expenses




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
    print("gsdags")
    try:
        res_type = resource_type
        if res_type == "audio":
            res_type = "video"
        # Upload the file to Cloudinary
        print(file_name)
        print(resource_type)
        print(res_type)
        print(file.file.readable())
        try:
            upload_result = cloudinary.uploader.upload(
               file.file,
               # public_id=f'TimeCapsuleMedia/{file_name}',
               resource_type=res_type,
               access_mode="public" 
            )
            print("Upload Successful")
        except Exception as upload_error:
            print(f"Error during upload: {upload_error}")
            raise HTTPException(status_code=500, detail="Failed to upload to Cloudinary")

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
        # Determine which type of media to return (either images or videos)
        if media_type == "image":
            media_files = group.get("uploaded_images", [])
        elif media_type == "video":
            media_files = group.get("uploaded_videos", [])
        elif media_type == "storie":
            media_files = group.get("uploaded_stories", [])
        else:
            raise HTTPException(status_code=400, detail="Invalid media type. Use 'image' or 'video' or 'stories'.")
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

# @app.post("/upload-story/{title}/{content}/{group_code}")
# async def upload_stories( title : str , content : str , group_code : str):
#     try:
#         # Check if group exists in the database
#         groups_collection = db.get_collection("TimeCapsuleMediaFiles")
#         user = await groups_collection.find_one({"group_code": group_code})  # Use await here

#         if user:
#             # If group exists, push the file details to the existing document
#             result = await groups_collection.update_one(  # Use await here
#                 {"group_code": group_code},
#                 {
#                     "$push": {
#                         f"uploaded_stories": {
#                             "title": title,
#                             f"content": content
#                         }
#                     }
#                 }
#             )
#             if result.modified_count == 0:
#                 raise HTTPException(status_code=500, detail=f"Failed to update group with story details")
#             print(f"{resource_type.capitalize()} added to existing user.")
#         else:
#             # If group does not exist, create a new user and add the file details
#              new_user = {
#                 "group_code": group_code,
#                 f"uploaded_{resource_type}s": [
#                     {
#                         "title": title,
#                         f"content": content
#                     }
#                 ]
#             }
#             await groups_collection.insert_one(new_user)  # Use await here
#             print(f"New user created and story details added.")

#         # Return the response directly as a dictionary
#         return {"message": "Story uploaded successfully"}

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
        
# @app.delete("/delete-story/{group_code}/{index}/")
# async def delete_story(group_code: str, index: int):
#     # Define the correct collection and media field
#     collection = db.get_collection("TimeCapsuleMediaFiles")
#     media_field = f"uploaded_stories"  # Either 'uploaded_images' or 'uploaded_videos'
    
#     # Find the document to ensure it exists
#     document = await collection.find_one({"group_code": group_code})
#     if not document:
#         raise HTTPException(status_code=404, detail="Group not found")
    
#     # Check if the index is valid for the selected media type
#     uploaded_media = document.get(media_field, [])
#     if index < 0 or index >= len(uploaded_media):
#         raise HTTPException(status_code=400, detail="Invalid index")

#     # Remove the media item from the list
#     uploaded_media.pop(index)
    
#     # Update the document in MongoDB
#     result = await collection.update_one(
#         {"group_code": group_code},
#         {"$set": {media_field: uploaded_media}}
#     )
    
#     if result.modified_count == 1:
#         return {"message": "story deleted successfully"}
#     else:
#         raise HTTPException(status_code=500, detail="Failed to delete story")

# @app.put("/update-story/{group_code}/{index}/{title}/{content}")
# async def update_story(group_code: str, index: int, title : str, content : str):
#     collection = db.get_collection("TimeCapsuleMediaFiles")
#     # Find the document to ensure it exists
#     document = await collection.find_one({"group_code": group_code})
#     if not document:
#         raise HTTPException(status_code=404, detail="Group not found")
    
#     media_field = f"uploaded_stories"  # Either 'uploaded_images' or 'uploaded_videos'
    
#     # Check if the index is valid for the chosen media type
#     if index < 0 or index >= len(document.get(media_field, [])):
#         raise HTTPException(status_code=400, detail="Invalid index")
    
#     result = await collection.update_one(
#         {"group_code": group_code},
#         {"$set": {f"{media_field}.{index}.title": title}}
#     )
    
#     if result.modified_count == 1:
#         return {"message": "story updated successfully"}
#     else:
#         raise HTTPException(status_code=500, detail="Failed to update story")

# @app.post("/upload-story/")
# async def upload_stories(group_code: str, title: str, content: str):
#     try:
#         # Access the collection
#         groups_collection = db.get_collection("TimeCapsuleMediaFiles")
#         print(group_code)
#         print(title)
#         print(content)
#         # Check if group exists
#         user = await groups_collection.find_one({"group_code": group_code})
#         if user:
#             print("hello i am here")
#             # Push the story details to the existing group
#             result = await groups_collection.update_one(
#                 {"group_code": group_code},
#                 {
#                     "$push": {
#                         "uploaded_stories": {
#                             "title": title,
#                             "content": content
#                         }
#                     }
#                 }
#             )
#             if result.modified_count == 0:
#                 raise HTTPException(status_code=500, detail="Failed to update group with story details")
#         else:
#             # Create a new group with the story details
#             print("no i am no here")
#             new_user = {
#                 "group_code": group_code,
#                 "uploaded_stories": [
#                     {
#                         "title": title,
#                         "content": content
#                     }
#                 ]
#             }
#             await groups_collection.insert_one(new_user)

#         return {"message": "Story uploaded successfully"}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

class StoryRequest(BaseModel):
    group_code: str
    title: str
    content: str

@app.post("/upload-story/")
async def upload_stories(request: StoryRequest):
    group_code = request.group_code
    title = request.title
    content = request.content

    try:
        # Access the collection
        groups_collection = db.get_collection("TimeCapsuleMediaFiles")
        print(f"group_code: {group_code}, title: {title}, content: {content}")

        # Check if group exists
        user = await groups_collection.find_one({"group_code": group_code})
        if user:
            print("Group exists, adding story")
            result = await groups_collection.update_one(
                {"group_code": group_code},
                {
                    "$push": {
                        "uploaded_stories": {
                            "title": title,
                            "content": content
                        }
                    }
                }
            )
            if result.modified_count == 0:
                raise HTTPException(status_code=500, detail="Failed to update group with story details")
        else:
            print("Group does not exist, creating new group")
            new_user = {
                "group_code": group_code,
                "uploaded_stories": [
                    {
                        "title": title,
                        "content": content
                    }
                ]
            }
            await groups_collection.insert_one(new_user)

        return {"message": "Story uploaded successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/delete-story/{group_code}/{index}")
async def delete_story(group_code: str, index: int):
    try:
        collection = db.get_collection("TimeCapsuleMediaFiles")
        document = await collection.find_one({"group_code": group_code})
        if not document:
            raise HTTPException(status_code=404, detail="Group not found")

        uploaded_media = document.get("uploaded_stories", [])
        if index < 0 or index >= len(uploaded_media):
            raise HTTPException(status_code=400, detail="Invalid index")

        uploaded_media.pop(index)

        result = await collection.update_one(
            {"group_code": group_code},
            {"$set": {"uploaded_stories": uploaded_media}}
        )

        if result.modified_count == 1:
            return {"message": "Story deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete story")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/update-story/{group_code}/{index}/{title}/{content}")
async def update_story(group_code: str, index: int, title: str, content: str):
    try:
        collection = db.get_collection("TimeCapsuleMediaFiles")
        document = await collection.find_one({"group_code": group_code})
        if not document:
            raise HTTPException(status_code=404, detail="Group not found")

        uploaded_media = document.get("uploaded_stories", [])
        if index < 0 or index >= len(uploaded_media):
            raise HTTPException(status_code=400, detail="Invalid index")

        # Update both title and content
        result = await collection.update_one(
            {"group_code": group_code},
            {
                "$set": {
                    f"uploaded_stories.{index}.title": title,
                    f"uploaded_stories.{index}.content": content
                }
            }
        )

        if result.modified_count == 1:
            return {"message": "Story updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update story")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


'''
#previous
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
#newwwwwwwww

@app.post("/categories/", response_model=dict)
async def create_category(info: CategoryCreate):
    """
    Add a user-created category to a group and create default folders.
    """
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")

    # Check if the group exists in the Categories collection
    group = await categories_collection.find_one({"group_code": info.group_code})

    if not group:
        # If group doesn't exist, create a new document for the group
        group_data = {
            "group_code": info.group_code,
            "categories": []
        }
        await categories_collection.insert_one(group_data)

    # Add the new category to the group's categories array
    category_data = {
        "category_name": info.category_name,
        "is_preset": False,  # User-created category
        "created_at": datetime.utcnow(),
    }
    category_id = ObjectId()
    await categories_collection.update_one(
        {"group_code": info.group_code},
        {"$push": {"categories": {"_id": category_id, **category_data}}}
    )

    # Create default folders for the new category
    default_folders = ["Docs", "Images", "Videos", "Music"]
    for folder_name in default_folders:
        folder_data = {
            "folder_name": folder_name,
            "category_id": str(category_id),
            "parent_folder_id": None,  # Default folders have no parent
            "created_at": datetime.utcnow(),
        }
        await folders_collection.insert_one(folder_data)

    return {
        "success": True,
        "message": "Category created successfully with default folders.",
        "category_id": str(category_id),
    }

@app.get("/categories/", response_model=dict)
async def get_categories(group_code: str):
    """
    Fetch categories for a specific group.
    Includes both preset and user-created categories.
    """
    categories_collection = db.get_collection("Categories")

    try:
        # Fetch the group document by group_code
        group = await categories_collection.find_one({"group_code": group_code})

        if not group:
            return {"success": True, "categories": []}  # Return empty if group not found

        # Serialize the categories within the group
        serialized_categories = [
            {
                "id": str(category["_id"]),
                "category_name": category["category_name"],
                "is_preset": category.get("is_preset", False),
                "created_at": category["created_at"].isoformat()
                if "created_at" in category else None,
            }
            for category in group.get("categories", [])
        ]

        return {"success": True, "categories": serialized_categories}

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


#previous
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

#previous
@app.get("/folders/{category_id}/")
async def get_folders(category_id: str, parent_folder_id: str = None):
    folders_collection = db.get_collection("Folders")
    query = {"category_id": category_id, "parent_folder_id": parent_folder_id}
    folders = await folders_collection.find(query).to_list(None)
    return [{"id": str(folder["_id"]), "folder_name": folder["folder_name"]} for folder in folders]



## 25.01.25 11.03
@app.put("/rename-folder/")
async def rename_folder(rename_info: RenameFolder):
    folders_collection = db.get_collection("Folders")

    # Find and update the folder's name
    result = await folders_collection.update_one(
        {"_id": ObjectId(rename_info.folder_id)},
        {"$set": {"folder_name": rename_info.new_name}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Folder not found")

    return {"success": True, "message": "Folder renamed successfully"}


## 25.01.25 11.03

@app.delete("/delete-folder/")
async def delete_folder(delete_info: DeleteFolder):
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    # Check if the folder exists
    folder = await folders_collection.find_one({"_id": ObjectId(delete_info.folder_id)})
    if not folder:
        raise HTTPException(status_code=404, detail="Folder not found")

    # Delete the folder
    await folders_collection.delete_one({"_id": ObjectId(delete_info.folder_id)})

    # Delete files associated with the folder
    await files_collection.delete_many({"folder_id": delete_info.folder_id})

    # Optionally, recursively delete subfolders
    subfolders = folders_collection.find({"parent_folder_id": delete_info.folder_id})
    async for subfolder in subfolders:
        await delete_folder(DeleteFolder(folder_id=str(subfolder["_id"])))

    return {"success": True, "message": "Folder and associated content deleted successfully"}


'''
#previous works correctly
# Upload file API
@app.post("/upload-file/")
async def upload_file(
    category_id: str = Form(...),
    folder_id: str = Form(...),
    file: UploadFile = File(...)
):
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    # Validate category and folder
    if not categories_collection.find_one({"_id": ObjectId(category_id)}):
        raise HTTPException(status_code=404, detail="Category not found")

    if not folders_collection.find_one({"_id": ObjectId(folder_id)}):
        raise HTTPException(status_code=404, detail="Folder not found")

    # Upload to Cloudinary
    try:
        result = cloudinary.uploader.upload(file.file, resource_type="auto")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

    # Save metadata to MongoDB
    file_data = {
        "file_name": file.filename,
        "category_id": category_id,
        "folder_id": folder_id,
        "cloudinary_url": result.get("secure_url"),
        "public_id": result.get("public_id"),
        "file_type": result.get("resource_type"),
        "created_at": datetime.utcnow(),
    }
    result =await files_collection.insert_one(file_data)

    return {"success": True, "file_id": str(result.inserted_id)}



'''
'''
#work properly only 
# Upload file API
@app.post("/upload-file/")
async def upload_file(
    category_id: str = Form(...),
    folder_id: str = Form(...),
    file: UploadFile = File(...)
):
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    # Validate category and folder
    if not categories_collection.find_one({"_id": ObjectId(category_id)}):
        raise HTTPException(status_code=404, detail="Category not found")

    if not folders_collection.find_one({"_id": ObjectId(folder_id)}):
        raise HTTPException(status_code=404, detail="Folder not found")

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(file.filename)

    # Set resource_type based on MIME type
    if mime_type and mime_type.startswith("image"):
        resource_type = "image"
    elif mime_type and mime_type.startswith("video"):
        resource_type = "video"
    elif mime_type and mime_type.startswith("audio"):
        resource_type = "video"  # Cloudinary handles audio as video type
    else:
        resource_type = "raw"  # For non-image/video/audio files (e.g., PDF)

    # Upload to Cloudinary
    try:
        result = cloudinary.uploader.upload(file.file, resource_type=resource_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

    # Save metadata to MongoDB
    file_data = {
        "file_name": file.filename,
        "category_id": category_id,
        "folder_id": folder_id,
        "cloudinary_url": result.get("secure_url"),
        "public_id": result.get("public_id"),
        "file_type": result.get("resource_type"),
        "created_at": datetime.utcnow(),
    }
    result = await files_collection.insert_one(file_data)

    return {"success": True, "file_id": str(result.inserted_id)}
'''
# Upload file API
@app.post("/upload-file/")
async def upload_file(
    category_id: str = Form(...),
    folder_id: str = Form(...),
    file: UploadFile = File(...)
):
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    # Validate category and folder
    if not categories_collection.find_one({"_id": ObjectId(category_id)}):
        raise HTTPException(status_code=404, detail="Category not found")

    if not folders_collection.find_one({"_id": ObjectId(folder_id)}):
        raise HTTPException(status_code=404, detail="Folder not found")

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(file.filename)

    # Set resource_type based on MIME type
    if mime_type and mime_type.startswith("image"):
        resource_type = "image"
    elif mime_type and mime_type.startswith("video"):
        resource_type = "video"
    elif mime_type and mime_type.startswith("audio"):
        resource_type = "video"  # Cloudinary handles audio as video type
    else:
        resource_type = "raw"  # For non-image/video/audio files (e.g., PDF)

    # Upload to Cloudinary with public access mode
    try:
        result = cloudinary.uploader.upload(
            file.file,
            resource_type=resource_type,
            access_mode="public"  # Explicitly set the file to be publicly accessible
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

    # Save metadata to MongoDB
    file_data = {
        "file_name": file.filename,
        "category_id": category_id,
        "folder_id": folder_id,
        "cloudinary_url": result.get("secure_url"),
        "public_id": result.get("public_id"),
        "file_type": result.get("resource_type"),
        "created_at": datetime.utcnow(),
    }
    result = await files_collection.insert_one(file_data)

    return {"success": True, "file_id": str(result.inserted_id)}



'''
@app.post("/upload-file/")
async def upload_file(
    category_id: str = Form(...),
    folder_id: str = Form(...),
    file: UploadFile = File(...)
):
    from mimetypes import guess_type

    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    # Validate category and folder
    if not categories_collection.find_one({"_id": ObjectId(category_id)}):
        raise HTTPException(status_code=404, detail="Category not found")

    if not folders_collection.find_one({"_id": ObjectId(folder_id)}):
        raise HTTPException(status_code=404, detail="Folder not found")

    # Detect MIME type of the file
    mime_type, _ = guess_type(file.filename)
    resource_type = "auto"  # Default

    # Map MIME type to resource type
    if mime_type:
        if mime_type.startswith("image"):
            resource_type = "image"
        elif mime_type.startswith("video"):
            resource_type = "video"
        elif mime_type.startswith("audio"):
            resource_type = "audio"
        elif mime_type.startswith("application"):
            resource_type = "raw"  # For docs like PDFs

    # Upload to Cloudinary with explicit resource type
    try:
        result = cloudinary.uploader.upload(file.file, resource_type=resource_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cloudinary upload failed: {str(e)}")

    # Save metadata to MongoDB
    file_data = {
        "file_name": file.filename,
        "category_id": category_id,
        "folder_id": folder_id,
        "cloudinary_url": result.get("secure_url"),
        "public_id": result.get("public_id"),
        "file_type": result.get("resource_type"),
        "created_at": datetime.utcnow(),
    }
    result = await files_collection.insert_one(file_data)

    return {"success": True, "file_id": str(result.inserted_id)}

'''

# Fetch files API
@app.get("/files/{folder_id}/")
async def get_files(folder_id: str):
    categories_collection = db.get_collection("Categories")
    folders_collection = db.get_collection("Folders")
    files_collection = db.get_collection("Files")

    files_cursor = files_collection.find({"folder_id": folder_id})
    files = await files_cursor.to_list(length=None)  # Convert the cursor to a list

    files_list = [
        {
            "id": str(file["_id"]),
            "file_name": file["file_name"],
            "cloudinary_url": file["cloudinary_url"],
            "file_type": file["file_type"],
            "created_at": file["created_at"].isoformat()
        }
        for file in files
    ]
    return files_list






