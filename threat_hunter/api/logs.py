from fastapi import APIRouter, Depends, HTTPException

from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.settings import get_threat_hunter_core

router = APIRouter()


@router.get("/api/logs/{log_id}")
async def get_log_details(log_id: str, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    for data in core.vector_db.metadata.values():
        sha = data.get("sha256")
        if sha and sha.startswith(log_id):
            return data
    raise HTTPException(status_code=404, detail="Log not found")
