from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os
from fastapi.middleware.cors import CORSMiddleware

# creating a FastAPI instance
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# MongoDB connection string (filling up with MongoDB Atlas credentials)
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client.get_database('FamNest')  
# collection1 = db.get_collection('email-password') 


# Defining the Pydantic model to handle incoming data
class InputText(BaseModel):
    input_text: str


# for user_registration
# name , email , password , joinCreate(by default : false) class 
class register(BaseModel):
    name: str
    email: str
    password: str

# Endpoint
@app.post("/save-input/")
async def save_input(info: register):
    name = info.name
    email = info.email
    password = info.password
    isJoinCreate = False

    collection = db.get_collection('Registerd_Users_Only')
    # Check if the input text already exists in the MongoDB collection
    existing_entry = collection.find_one({"email": email})

    if existing_entry:
        return {"message": "This Email is Already Taken", "status": "error"}  # Return error if already exists
    else:
        # Insert the new input text into the database
        collection.insert_one({"name":name, "email": email, "password":password , "Joined or Created any Group": isJoinCreate})
        return {"message": "Successfully Registered", "status": "success"}  # Success message if inserted

# for user_login
# email , password class 
class login(BaseModel):
    email: str
    password: str
    
@app.post("/check-input/")
async def check_input(info : login):
    email = info.email
    password = info.password
 
    collection = db.get_collection('Registerd_Users_Only')
    # Check if the input text already exists in the MongoDB collection
    existing_entry = collection.find_one({"email": email, "password":password})

    if existing_entry:
        return {"message": "Login Successful", "status": "success"}  # Success message if inserted
    else:
        return {"message": "Incorrect Email or Password", "status": "success"}  # Return error if already exists

# for creation of groups (collection = logged in successfully , {name , email , AtLeastOneGroup , groups})
# called from create join page
class groupCreate(BaseModel):
   email : str
   new_group : str

@app.post("/group-create/")
async def group_create(info: groupCreate):
    email = info.email
    new_group = info.new_group
    User = db.get_collection("Registerd_Users_Only")
    User_Info = User.find_one({"email": email})  # Find user by email

    if not User_Info:
        return {"error": "User not found with the given email"}

    # Perform your operations
    name = User_Info.get("name")
    password = User_Info.get("password")
    collection = db.get_collection("Users Logged in Successfully with a Group")
    collection.update_one(
        {"email": email}, 
        {
            "$set": {"name": name, "password": password, "AtLeastOneGroup": True},
            "$push": {"groups": new_group}
        },
        upsert=True
    )

# for checking whether to show Join Create Group page or not
# called from login page
class email(BaseModel):
    email : str
@app.post("/check-one-group-criteria/")
async def check_one_group_criteria(info : email):
    email = info.email
    collection = db.get_collection("Users Logged in Successfully with a Group")
    existing_entry = collection.find_one({"email":email})
    return {"exists": bool(existing_entry)}
   
