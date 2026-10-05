from pydantic import BaseModel, Field
from typing import Optional

class Class10Input(BaseModel):
    math_marks: float = Field(..., ge=0, le=100)
    science_marks: float = Field(..., ge=0, le=100)
    english_marks: float = Field(..., ge=0, le=100)
    social_marks: float = Field(60.0, ge=0, le=100)
    hindi_marks: float = Field(60.0, ge=0, le=100)
    tech_interest: int = Field(5, ge=0, le=10)
    commerce_interest: int = Field(5, ge=0, le=10)
    art_interest: int = Field(5, ge=0, le=10)

    class Config:
        extra = "forbid"

class Class12Input(BaseModel):
    stream: str = Field(..., pattern="^(Science|Commerce|Arts)$")
    marks_subject1: float = Field(..., ge=0, le=100)
    marks_subject2: float = Field(..., ge=0, le=100)
    marks_subject3: float = Field(..., ge=0, le=100)
    math_marks: float = Field(60.0, ge=0, le=100)
    physics_marks: float = Field(60.0, ge=0, le=100)
    bio_marks: float = Field(60.0, ge=0, le=100)
    preferred_subject: str = Field("Mathematics", max_length=50)
    skills_count: int = Field(3, ge=0, le=20)

    class Config:
        extra = "forbid"

class CollegeInput(BaseModel):
    degree: str = Field("B.Tech / B.E.", max_length=100)
    cgpa: float = Field(..., ge=0.0, le=10.0)
    skills_count: int = Field(5, ge=0, le=20)
    projects_count: int = Field(2, ge=0, le=20)
    internships_count: int = Field(1, ge=0, le=10)
    certifications: int = Field(2, ge=0, le=20)
    active_backlogs: int = Field(0, ge=0, le=20)

    class Config:
        extra = "forbid"

class PositionInput(BaseModel):
    role: str = Field(..., pattern="^(class10|class12|college|graduate)$")
    overall_score: float = Field(..., ge=0, le=100)
    skills_count: int = Field(3, ge=0, le=20)
    extra_score: float = Field(0.0)

    class Config:
        extra = "forbid"

class SeniorMatchInput(BaseModel):
    class10_percentage: float = Field(60.0, ge=0, le=100)
    stream: str = Field("Science", pattern="^(Science|Commerce|Arts)$")
    cgpa: float = Field(7.0, ge=0.0, le=10.0)
    skills_count: int = Field(4, ge=0, le=20)
    top_n: int = Field(3, ge=1, le=10)

    class Config:
        extra = "forbid"

class OldProfile(BaseModel):
    stage: int
    stream: int
    marks: float
    skills_count: int

    class Config:
        extra = "forbid"

class OldComparison(BaseModel):
    profile1: OldProfile
    profile2: OldProfile

    class Config:
        extra = "forbid"
