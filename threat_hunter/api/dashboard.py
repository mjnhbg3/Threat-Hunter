
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.settings import get_threat_hunter_core

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def get_dashboard():
    with open("threat_hunter/templates/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@router.get("/api/dashboard")
async def get_dashboard_data(core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    return core.get_dashboard_data()

@router.post("/api/analyze")
async def trigger_analysis(core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    asyncio.create_task(core.analyze_threats())
    return {"message": "Analysis triggered"}
