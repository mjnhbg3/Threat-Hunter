import asyncio
from datetime import datetime
from typing import List, Dict, Any

from threat_hunter.core.vector_db import VectorDB
from threat_hunter.core.gemini import Gemini
from threat_hunter.core.wazuh import WazuhAPI
from threat_hunter.utils.logger import logger


class ThreatHunterCore:
    """Main orchestrator for log processing and threat analysis."""

    def __init__(self, api_keys: List[str], wazuh_api: WazuhAPI, db_dir: str = "./db"):
        self.vector_db = VectorDB(db_dir)
        self.gemini = Gemini(api_keys)
        self.wazuh = wazuh_api
        self.status = "Initializing"
        self.last_run: str | None = None
        self.issues: List[Dict[str, Any]] = []

    async def process_logs(self) -> List[Dict[str, Any]]:
        self.status = "processing"
        logs = await self.wazuh.read_new_logs()
        if logs:
            self.vector_db.add_documents(logs)
            self.vector_db.save()
        self.status = "ready"
        self.last_run = datetime.utcnow().isoformat()
        return logs

    async def analyze(self, recent_logs: List[Dict[str, Any]]):
        if not recent_logs:
            return
        self.status = "analyzing"
        logs_str = "\n".join([str(l) for l in recent_logs[:20]])
        prompt = (
            "Analyze the following security logs and identify any new security issues.\n"
            f"Logs:\n{logs_str}\n"
            "Respond in JSON with fields: severity, title, summary, recommendation."
        )
        text = await self.gemini.generate(prompt, max_tokens=512)
        try:
            issue = {
                "id": f"TH-{len(self.issues)+1:03d}",
                "title": text.split("\n")[0][:64],
                "summary": text,
                "recommendation": "Review the logs",
                "severity": "Medium",
                "timestamp": datetime.utcnow().isoformat(),
                "related_logs": []
            }
            self.issues.append(issue)
        except Exception as e:
            logger.error("Failed to parse Gemini response: %s", e)
        self.status = "ready"

    def get_dashboard_data(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "last_run": self.last_run,
            "summary": "Threat hunter operational",
            "issues": self.issues,
            "stats": {
                "total_logs": self.vector_db.index.ntotal,
                "anomalies": len(self.issues),
            },
            "log_trend": [],
            "rule_distribution": {},
            "active_api_key_index": self.gemini.current,
        }
