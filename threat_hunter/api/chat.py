from fastapi import APIRouter, Depends
from pydantic import BaseModel

from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.settings import get_threat_hunter_core

router = APIRouter()


class ChatQuery(BaseModel):
    query: str
    history: list = []


@router.post("/api/chat/analyze")
async def analyze_chat(
    query: ChatQuery,
    core: ThreatHunterCore = Depends(get_threat_hunter_core),
):
    return {"plan": "simple_search"}


@router.post("/api/chat/execute")
async def execute_chat(
    query: ChatQuery,
    core: ThreatHunterCore = Depends(get_threat_hunter_core),
):
    answer = await core.gemini.generate(
        query.query,
        max_tokens=core.settings.get("max_output_tokens", 256),
    )
    return {"answer": answer}
