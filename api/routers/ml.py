from fastapi import APIRouter, Depends, HTTPException
import pandas as pd
import numpy as np
import os
import json
from schemas.ml import Class10Input, Class12Input, CollegeInput, PositionInput, SeniorMatchInput
from core.dependencies import require_roles, get_current_user
from core.model_loader import secure_load_pickle
from core.db import save_prediction
import uuid

router = APIRouter()

# Load Models
m_stream = secure_load_pickle("class10_stream_model.pkl")
enc_stream = secure_load_pickle("class10_stream_encoder.pkl")
m_course = secure_load_pickle("class12_course_model.pkl")
enc_stream12 = secure_load_pickle("class12_stream_encoder.pkl")
enc_pref12 = secure_load_pickle("class12_pref_encoder.pkl")
enc_course12 = secure_load_pickle("class12_course_encoder.pkl")
m_domain_dt = secure_load_pickle("college_domain_model_dt.pkl")
m_domain_lr = secure_load_pickle("college_domain_model_lr.pkl")
enc_degree = secure_load_pickle("college_degree_encoder.pkl")
enc_domain = secure_load_pickle("college_domain_encoder.pkl")
m_salary_rf = secure_load_pickle("salary_rf_model.pkl")
m_salary_lin = secure_load_pickle("salary_linear_model.pkl")
m_salary_old = secure_load_pickle("salary_model.pkl")
m_success_old = secure_load_pickle("success_model.pkl")

# Load Alumni Data securely
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def load_alumni():
    path = os.path.join(BASE_DIR, "data", "alumni_seniors.csv")
    if not os.path.exists(path):
        return pd.DataFrame()
    return pd.read_csv(path)
alumni_df = load_alumni()

def safe_encode(encoder, value, default=0):
    if encoder is None:
        return default
    try:
        return int(encoder.transform([value])[0])
    except Exception:
        return default

@router.post("/predict/stream")
async def predict_stream(data: Class10Input, user=Depends(get_current_user)):
    try:
        features = np.array([[
            data.math_marks, data.science_marks, data.english_marks,
            data.social_marks, data.hindi_marks, data.tech_interest,
            data.commerce_interest, data.art_interest
        ]])
        if m_stream is None:
            pred = "Science"
        else:
            p = m_stream.predict(features)[0]
            pred = enc_stream.inverse_transform([p])[0] if enc_stream else "Science"
        
        result = {"recommended_stream": pred}
        await save_prediction(user["sub"], "class10", data.dict(), result)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail="Prediction failed")

@router.post("/predict/course")
async def predict_course(data: Class12Input, user=Depends(get_current_user)):
    try:
        s_enc = safe_encode(enc_stream12, data.stream, 0)
        p_enc = safe_encode(enc_pref12, data.preferred_subject, 0)
        features = np.array([[
            s_enc, data.marks_subject1, data.marks_subject2,
            data.marks_subject3, data.math_marks, data.physics_marks,
            data.bio_marks, p_enc, data.skills_count
        ]])
        if m_course is None:
            pred = "Engineering"
        else:
            p = m_course.predict(features)[0]
            pred = enc_course12.inverse_transform([p])[0] if enc_course12 else "Engineering"
        
        result = {"recommended_course": pred}
        await save_prediction(user["sub"], "class12", data.dict(), result)
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Prediction failed")

@router.post("/seniors/match")
async def seniors_match(data: SeniorMatchInput, user=Depends(get_current_user)):
    if alumni_df.empty:
        return {"matches": []}
    df = alumni_df.copy()
    try:
        score = (
            2.0 * (100 - abs(df["Class10_Marks"] - data.class10_percentage)) +
            3.0 * (10 - abs(df["College_CGPA"] - data.cgpa)) * 10 +
            1.5 * (20 - abs(df["Skills_Count"] - data.skills_count)) * 5
        )
        score += np.where(df["Stream"] == data.stream, 50, 0)
        df["match_score"] = score
        top = df.sort_values("match_score", ascending=False).head(data.top_n)
        return {"matches": top.to_dict(orient="records")}
    except Exception:
        raise HTTPException(status_code=500, detail="Match failed")
