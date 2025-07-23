from fastapi import APIRouter, Depends
from pydantic import BaseModel
from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.settings import get_threat_hunter_core

router = APIRouter()

class IssueQuery(BaseModel):
    query: str
    history: list = []

@router.post("/api/issues/{issue_id}/ignore")
async def ignore_issue(issue_id: str, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    # Placeholder for ignore logic
    return {"message": f"Issue {issue_id} ignored"}

@router.post("/api/issues/{issue_id}/query")
async def query_issue(issue_id: str, query: IssueQuery, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    # Placeholder for issue query logic
    response = core.gemini.generate_content(f"User query about issue {issue_id}: {query.query}\n\nProvide a helpful response.")
    return {"answer": response}

@router.post("/api/issues/{issue_id}/generate-script")
async def generate_script(issue_id: str, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    # Placeholder for script generation logic
    script = core.gemini.generate_content(f"Generate a diagnosis and repair script for issue {issue_id}.")
    return {"script": script}
