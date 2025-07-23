from datetime import datetime, timedelta
from collections import defaultdict
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
        self.log_timestamps: list[datetime] = []
        self.rule_counts: dict[str, int] = defaultdict(int)
        self.new_logs: int = 0

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
        self.new_logs = len(logs)
        if logs:
            self.vector_db.add_documents(logs)
            self.vector_db.save()
            now = datetime.utcnow()
            for entry in logs:
                ts_str = entry.get("timestamp") or entry.get("@timestamp")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        self.log_timestamps.append(ts)
                    except Exception:
                        pass
                rule = entry.get("rule") or {}
                if isinstance(rule, dict):
                    desc = rule.get("description") or str(rule.get("id"))
                    if desc:
                        self.rule_counts[desc] += 1
            self._save_state()
            # keep only last hour of timestamps
            cutoff = now - timedelta(hours=1)
            self.log_timestamps = [t for t in self.log_timestamps if t >= cutoff]
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
            issue = {
                "id": f"TH-{len(self.issues)+1:03d}",
                "title": text.split("\n")[0][:64],
                "summary": text,
                "recommendation": "Review the logs",
                "severity": "Medium",
                "timestamp": datetime.utcnow().isoformat(),
                "related_logs": []
            }
            if issue["id"] not in self.ignored:
                self.issues.append(issue)
                self._save_state()
        except Exception as e:
            logger.error("Failed to parse Gemini response: %s", e)
        self.status = "ready"

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Return status information and recent activity for the UI."""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=1)
        trend_counts: dict[str, int] = defaultdict(int)
        for ts in self.log_timestamps:
            if ts >= cutoff:
                trend_counts[ts.strftime("%H:%M")] += 1

        trend = [
            {"time": t, "count": trend_counts[t]}
            for t in sorted(trend_counts.keys())
        ]

        return {
            "status": self.status,
            "last_run": self.last_run,
            "summary": "Threat hunter operational",
            "issues": self.issues,
            "stats": {
                "total_logs": self.vector_db.index.ntotal,
                "new_logs": self.new_logs,
                "anomalies": len(self.issues),
            },
            "log_trend": trend,
            "rule_distribution": dict(self.rule_counts),
            "active_api_key_index": self.gemini.current,
        }

    # ------------------------------------------------------------------
    def ignore_issue(self, issue_id: str) -> None:
        """Remove an issue and persist the ignore list."""
        self.issues = [i for i in self.issues if i.get("id") != issue_id]
        self.ignored.add(issue_id)
        self._save_state()
