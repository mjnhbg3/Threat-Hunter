from datetime import datetime
from typing import List, Dict, Any

import json
import os

from threat_hunter.core.vector_db import VectorDB
from threat_hunter.core.gemini import Gemini
from threat_hunter.core.metrics import MetricsCollector
from threat_hunter.core.wazuh import WazuhAPI
from threat_hunter.utils.logger import logger


class ThreatHunterCore:
    """Main orchestrator for log processing and threat analysis."""

    def __init__(self, api_keys: List[str], wazuh_api: WazuhAPI, db_dir: str = "./db"):
        self.db_dir = db_dir
        self.dashboard_path = os.path.join(db_dir, "dashboard.json")
        self.ignore_path = os.path.join(db_dir, "ignored.json")

        self.vector_db = VectorDB(db_dir)
        self.metrics = MetricsCollector()
        self.gemini = Gemini(api_keys, metrics=self.metrics)
        self.wazuh = wazuh_api
        self.status = "Initializing"
        self.last_run: str | None = None
        self.issues: List[Dict[str, Any]] = []
        self.ignored: set[str] = set()

        self._load_state()

    # ------------------------------------------------------------------
    def _load_state(self) -> None:
        """Load persisted issues and ignore list from disk."""
        if os.path.exists(self.dashboard_path):
            try:
                with open(self.dashboard_path, "r") as f:
                    data = json.load(f)
                    self.issues = data.get("issues", [])
                    self.last_run = data.get("last_run")
            except Exception as exc:  # pragma: no cover - best effort
                logger.error("Failed to load dashboard state: %s", exc)

        if os.path.exists(self.ignore_path):
            try:
                with open(self.ignore_path, "r") as f:
                    self.ignored = set(json.load(f))
            except Exception as exc:
                logger.error("Failed to load ignored issues: %s", exc)

    def _save_state(self) -> None:
        """Persist issues and ignore list to disk."""
        try:
            payload = {"issues": self.issues, "last_run": self.last_run}
            os.makedirs(self.db_dir, exist_ok=True)
            with open(self.dashboard_path, "w") as f:
                json.dump(payload, f)
            with open(self.ignore_path, "w") as f:
                json.dump(list(self.ignored), f)
        except Exception as exc:  # pragma: no cover - best effort
            logger.error("Failed to save dashboard state: %s", exc)

    async def process_logs(self) -> List[Dict[str, Any]]:
        self.status = "processing"
        logs = await self.wazuh.read_new_logs()
        if logs:
            await self.vector_db.add_documents(logs)
            await self.vector_db.save()
            self._save_state()
        self.status = "ready"
        self.last_run = datetime.utcnow().isoformat()
        return logs

    async def analyze(self, recent_logs: List[Dict[str, Any]]):
        if not recent_logs:
            return
        self.status = "analyzing"
        logs_str = "\n".join([str(entry) for entry in recent_logs[:20]])
        prompt = (
            "Analyze the following security logs and identify any new security issues.\n"
            f"Logs:\n{logs_str}\n"
            "Respond in JSON with fields: severity, title, summary, recommendation."
        )
        text = await self.gemini.generate(prompt, max_tokens=512)
        try:
            next_id = len(self.issues) + len(self.ignored) + 1
            issue = {
                "id": f"TH-{next_id:03d}",
                "title": text.split("\n")[0][:64],
                "summary": text,
                "recommendation": "Review the logs",
                "severity": "Medium",
                "timestamp": datetime.utcnow().isoformat(),
                "related_logs": []
            }
            if issue["id"] in self.ignored:
                return
            if any(i.get("id") == issue["id"] for i in self.issues):
                return
            self.issues.append(issue)
            self._save_state()
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
            "active_api_key_index": self.gemini.active_key_index,
        }

    async def get_metrics_text(self) -> str:
        return await self.metrics.render()

    # ------------------------------------------------------------------
    def ignore_issue(self, issue_id: str) -> None:
        """Remove an issue and persist the ignore list."""
        self.issues = [i for i in self.issues if i.get("id") != issue_id]
        self.ignored.add(issue_id)
        self._save_state()

    async def periodic_worker(self, interval: int) -> None:
        """Continuously process logs and analyze them at a fixed interval."""
        import time

        while True:
            start = time.monotonic()
            logs = await self.process_logs()
            await self.analyze(logs)
            cycle = time.monotonic() - start
            await self.metrics.set_cycle_time(cycle)
            await asyncio.sleep(interval)
