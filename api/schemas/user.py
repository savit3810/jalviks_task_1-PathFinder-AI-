from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional

class UserCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)
    role: str = Field(..., pattern="^(class10|class12|college|graduate|parent|admin|viewer)$")
    linkedChildCode: Optional[str] = Field(None, max_length=50)
    careerGoal: Optional[str] = Field(None, max_length=100)
    
    class Config:
        extra = "forbid"

class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1)
    
    class Config:
        extra = "forbid"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: Optional[str] = None

class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str

class MFAVerify(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=6)
    
    class Config:
        extra = "forbid"
