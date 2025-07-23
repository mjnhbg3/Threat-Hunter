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
    core.issues = [i for i in core.issues if i["id"] != issue_id]
    return {"message": f"Issue {issue_id} ignored"}


@router.post("/api/issues/{issue_id}/query")
async def query_issue(issue_id: str, query: IssueQuery, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    answer = await core.gemini.generate(query.query, max_tokens=256)
    return {"answer": answer}


@router.post("/api/issues/{issue_id}/generate-script")
async def generate_script(issue_id: str, core: ThreatHunterCore = Depends(get_threat_hunter_core)):
    script = await core.gemini.generate(
        f"Generate a bash script to remediate issue {issue_id}", max_tokens=200
    )
    return {"script": script}
