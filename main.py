from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
from jose import jwt, JWTError
import os
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# MongoDB connection string (replace with your MongoDB Atlas credentials)
MONGO_URI = os.getenv("mongodb+srv://faiazmahmudifti:hello12345@cluster0.2yjx4.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
client = MongoClient(MONGO_URI)
db = client.get_database('FamNest')  # Replace with your database name
collection1 = db.get_collection('email-password')  # Replace with your collection name


# Define the Pydantic model to handle incoming data
class InputText(BaseModel):
    input_text: str


# Endpoint to check if the input already exists in the database and insert if not

# for user_registration
# name , email , password , joinCreate(by default : false) class 
class register(BaseModel):
    name: str
    email: str
    password: str
    
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
