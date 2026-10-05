import pickle
import hashlib
import json
import os
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(BASE_DIR, "ml_models", "manifest.json")

def load_manifest():
    if not os.path.exists(MANIFEST_PATH):
        return {}
    with open(MANIFEST_PATH, "r", encoding="utf-8-sig") as f:
        return json.load(f)

manifest = load_manifest()

def secure_load_pickle(filename: str):
    path = os.path.join(BASE_DIR, "ml_models", filename)
    if not os.path.exists(path):
        logging.warning(f"Model file {filename} not found.")
        return None
    
    # Calculate SHA256 hash of the file
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    file_hash = sha256_hash.hexdigest()
    
    # Check against manifest
    expected_hash = manifest.get(filename)
    if not expected_hash:
        raise ValueError(f"Security Error: Hash for {filename} not found in manifest.")
    
    if file_hash != expected_hash:
        raise ValueError(f"Security Error: Hash mismatch for {filename}. Expected {expected_hash}, got {file_hash}.")
    
    # If hash matches, it's safe to load
    with open(path, "rb") as f:
        return pickle.load(f)
