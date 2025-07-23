import asyncio
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.settings import get_threat_hunter_core

router = APIRouter()


class SettingsModel(BaseModel):
    processing_interval: int | None = None
    initial_scan_count: int | None = None
    log_batch_size: int | None = None
    search_k: int | None = None
    analysis_k: int | None = None
    max_issues: int | None = None
    max_output_tokens: int | None = None


@router.get("/", response_class=HTMLResponse)
async def get_dashboard():
    with open("threat_hunter/templates/index.html", "r") as f:
        return HTMLResponse(content=f.read())


@router.get("/api/dashboard")
async def get_dashboard_data(
    core: ThreatHunterCore = Depends(get_threat_hunter_core),
):
    return core.get_dashboard_data()


@router.post("/api/analyze")
async def trigger_analysis(
    core: ThreatHunterCore = Depends(get_threat_hunter_core),
):
    async def run():
        logs = await core.process_logs()
        await core.analyze(logs)
    asyncio.create_task(run())
    return {"message": "Analysis started"}


@router.get("/api/settings")
async def get_settings(core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    return core.settings


@router.post("/api/settings")
async def update_settings(
    settings: SettingsModel,
    core: ThreatHunterCore = Depends(get_threat_hunter_core),
):
    core.update_settings(settings.dict(exclude_none=True))
    return {"message": "Settings updated"}


@router.post("/api/clear_db")
async def clear_db(core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    await core.clear_database()
    return {"message": "Database cleared"}
