from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr
import bcrypt
import jwt
from bson import ObjectId
from datetime import datetime, timedelta,timezone
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

#FastAPI
app = FastAPI()

port = 3000

security = HTTPBearer()

#MongoDb Connection
MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME")

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
users_collection = db["users"]

print("MongoDB Connected")

#JWT
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", "24"))

#user Validation
class UserRegister(BaseModel):
    name: str
    email:EmailStr
    password:str
    role:str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password:str

class UserUpdate(BaseModel):
    name:str
    email:EmailStr
    password:str

#sanitize user
def sanitize_user(user):

    return{
        "id":str(user["_id"]),
        "name":user["name"],
        "email":user["email"],
        "role":user["role"]
    }

#Create JWT token
def create_token(user):
    payload = {
        "userId":str(user["_id"]),
        "email":user["email"],
        "role":user["role"],
        "exp":datetime.now(timezone.utc) + timedelta(hours=24)

    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token

#Authontication Middleware
def auth_middleware(credentials:HTTPAuthorizationCredentials = Depends(security)):

    try:
        token = credentials.credentials
        decode_token = jwt.decode(token,JWT_SECRET,algorithms=[JWT_ALGORITHM])
        user_id = decode_token["userId"]
        user = users_collection.find_one({"_id":ObjectId(user_id)})

        if not user:
            raise HTTPException(status_code=403,detail="Unauthorized exception")

        return user

    except HTTPException:
        raise

    except Exception as error:
        print("Authorization error:",error)
        raise HTTPException(status_code=403,detail="Invalid or expired token")

#authorize Role
def authorize_role(user,allowed_roles):

    if user["role"] not in allowed_roles:
        raise HTTPException(status_code=403,detail="You are not allowed to access this role")

    return True

#Register

@app.post("/register")
def register(user:UserRegister):

    existing_user = users_collection.find_one({"email":user.email})

    if existing_user:
        raise HTTPException(status_code=409, detail="User alredy existed")

    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"),bcrypt.gensalt())

    new_user = {
        "name": user.name,
        "email": user.email,
        "password": hashed_password.decode("utf-8"),
        "role": user.role
    }

    result = users_collection.insert_one(new_user)
    created_user = users_collection.find_one({"_id": result.inserted_id})

    token = create_token(created_user)

    return {
        "user": sanitize_user(created_user),
        "token": token,
        "message": "User registered successfully",
    }

#login
@app.post("/login")
def login(user:UserLogin):

    existing_user = users_collection.find_one({"email":user.email})

    if not existing_user:
        raise HTTPException(status_code=401,detail="Invalid email or password")

    password_match = bcrypt.checkpw(
        user.password.encode("utf-8"),existing_user["password"].encode("utf-8"))

    if not password_match:
        raise HTTPException(status_code=401,detail="Invalid email or password")

    token = create_token(existing_user)

    return {
        "user": sanitize_user(existing_user),
        "token":token,
        "message":"Login Successful"
    }

#get all users
@app.get("/userdetailes")
def get_users(current_user=Depends(auth_middleware)):

    authorize_role(current_user, ["admin"])

    users = users_collection.find()

    user_list = []

    for user in users:
        user_list.append(sanitize_user(user))

    return {"user": user_list, "message": "Users fetched successfully"}

#getbyid
@app.get("/usergetid/{id}")
def user_get_by_id(id:str, current_user=Depends(auth_middleware)):

    user = users_collection.find_one({"_id":ObjectId(id)})

    if not user:
        raise HTTPException(status_code=404,detail="User not found")

    return {"user":sanitize_user(user),"message":"User fetched successfully"}

#useredit
@app.put("/edituser/{id}")
def update_user(id:str, user_data:UserUpdate,current_user=Depends(auth_middleware)):

    authorize_role(current_user,["user","admin"])

    if str(current_user["_id"]) != id:
        raise HTTPException(status_code=403,detail="You can only edit your own account")

    hashed_password = bcrypt.hashpw(
        user_data.password.encode("utf-8"), bcrypt.gensalt()
    )

    update_data = {
        "name":user_data.name,
        "email":user_data.email,
        "password":hashed_password.decode("utf-8")
    }

    result = users_collection.update_one({"_id":ObjectId(id)},{"$set": update_data})

    if result.matched_count == 0:
        raise HTTPException(status_code=404,detail="User not found")

    updated_user = users_collection.find_one({"_id":ObjectId(id)})

    return{ "user":sanitize_user(updated_user), "message":"User updated successfully"}

#delete user
@app.delete("/deletinguser/{id}")
def delete_user(id: str, current_user=Depends(auth_middleware)):

    authorize_role(current_user,["user","admin"])

    if str(current_user["_id"]) != id:
        raise HTTPException(status_code=403,detail="You can only delete your own account")

    result = users_collection.find_one_and_delete({"_id":ObjectId(id)})

    if not result:
        raise HTTPException(status_code=404,detail="User not found")

    return{"user":sanitize_user(result),"message":"User deleted successfully"}