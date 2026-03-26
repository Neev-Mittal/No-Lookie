"""
QRIE API Server — Serves scanner, risk, and simulation engine outputs
Extends scanner_api.py with endpoints for asset inventory, CBOM, PQC posture, etc.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import json
import os
from pathlib import Path

app = FastAPI(title="QRIE Data API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data directory path
DATA_DIR = Path(__file__).parent.parent / "public" / "data"

def load_json_file(filename: str):
    """Load and return JSON file from data directory."""
    file_path = DATA_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
    
    with open(file_path, 'r') as f:
        return json.load(f)

# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    """Health check."""
    return { "status": "ok", "message": "QRIE API Server is running" }

@app.get("/api/assets")
async def get_assets(limit: int = 100):
    """Get asset inventory from CBOM."""
    try:
        data = load_json_file("pnb/cbom.json")
        # Limit results
        if limit and 'records' in data:
            data['records'] = data['records'][:limit]
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cbom")
async def get_cbom():
    """Get Cryptographic Bill of Materials."""
    return await get_assets()

@app.get("/api/subdomains")
async def get_subdomains(limit: int = 100):
    """Get discovered subdomains."""
    try:
        data = load_json_file("pnb/subdomains.json")
        if limit and 'subdomains' in data:
            data['subdomains'] = data['subdomains'][:limit]
        return data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/shadow-crypto")
async def get_shadow_crypto():
    """Get shadow cryptography findings."""
    try:
        return load_json_file("risk/shadow-crypto.json")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/pqc-posture")
async def get_pqc_posture():
    """Get PQC readiness posture."""
    try:
        return load_json_file("pnb/cbom.json")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cyber-rating")
async def get_cyber_rating():
    """Get cyber risk rating."""
    try:
        return load_json_file("risk/enriched_cbom.json")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/business-impact")
async def get_business_impact():
    """Get business impact simulation results."""
    try:
        data = load_json_file("simulation.json")
        return {"records": data if isinstance(data, list) else [data]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
