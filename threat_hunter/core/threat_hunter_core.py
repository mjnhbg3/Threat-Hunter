from datetime import datetime
from typing import List, Dict, Any

import hashlib

import json
import os

from threat_hunter.core.vector_db import VectorDB
from threat_hunter.core.gemini import Gemini
from threat_hunter.core.metrics import MetricsCollector
from threat_hunter.core.wazuh import WazuhAPI
from threat_hunter.utils.logger import logger


def summarize_logs(logs: List[Dict[str, Any]], limit: int = 20) -> str:
    """Return a newline separated summary of the provided log entries."""
    lines = []
    for log in logs[:limit]:
        if isinstance(log, dict):
            lines.append(json.dumps(log, sort_keys=True))
        else:
            lines.append(str(log))
    return "\n".join(lines)


def generate_retrieval_queries(text: str) -> List[str]:
    """Parse Gemini output into a list of retrieval queries."""
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("queries", data)
        if isinstance(data, list):
            return [str(q) for q in data if q]
    except json.JSONDecodeError:
        pass
    return [q.strip("-* \n") for q in text.splitlines() if q.strip()]


def extract_json_from_string(text: str) -> Any:
    """Extract the first valid JSON object or array from text."""
    starts = [text.find("{"), text.find("[")]
    starts = [i for i in starts if i != -1]
    start = min(starts) if starts else -1
    if start == -1:
        return None
    stack = []
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch in "[{":
            stack.append(ch)
        elif ch in "]}":
            if not stack:
                break
            stack.pop()
            if not stack:
                snippet = text[start : idx + 1]
                try:
                    return json.loads(snippet)
                except json.JSONDecodeError:
                    break
    return None


def generate_issue_signature(issue: Dict[str, Any]) -> str:
    """Create a stable signature string for deduplication."""
    parts = [issue.get("title", ""), issue.get("summary", "")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


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
        self.log_trend: List[Dict[str, Any]] = []
        self.rule_distribution: Dict[str, int] = {}

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
                    self.log_trend = data.get("log_trend", [])
                    self.rule_distribution = data.get("rule_distribution", {})
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
            payload = {
                "issues": self.issues,
                "last_run": self.last_run,
                "log_trend": self.log_trend,
                "rule_distribution": self.rule_distribution,
            }
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
            self.vector_db.add_documents(logs)
            self.vector_db.save()
            self._update_metrics(logs)
            await self.analyze_context_and_identify_issues(logs)
        self.last_run = datetime.utcnow().isoformat()
        self.status = "ready"
        self._save_state()
        return logs

    async def analyze_context_and_identify_issues(
        self, recent_logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze recent logs with historical context and store new issues."""
        if not recent_logs:
            return []

        self.status = "analyzing"

        recent_summary = summarize_logs(recent_logs)

        q_prompt = (
            "Generate a JSON array of short search queries that would help "
            "investigate these logs:\n" + recent_summary
        )
        queries_text = await self.gemini.generate(q_prompt, max_tokens=128)
        queries = generate_retrieval_queries(queries_text)

        history_logs: List[Dict[str, Any]] = []
        for q in queries:
            history_logs.extend(self.vector_db.search(q, k=3))

        history_summary = summarize_logs(history_logs)

        i_prompt = (
            "Using the recent logs and historical context provided, "
            "identify any security issues. Respond in JSON array with fields: "
            "severity, title, summary, recommendation."\
        )
        i_prompt += f"\nRecent Logs:\n{recent_summary}\nContext Logs:\n{history_summary}"
        resp = await self.gemini.generate(i_prompt, max_tokens=512)
        issues = extract_json_from_string(resp) or []
        new_issues = []
        if isinstance(issues, dict):
            issues = [issues]
        if isinstance(issues, list):
            for item in issues:
                if not isinstance(item, dict):
                    continue
                sig = generate_issue_signature(item)
                if sig in self.ignored or any(i.get("signature") == sig for i in self.issues):
                    continue
                issue = {
                    **item,
                    "id": f"TH-{len(self.issues)+len(new_issues)+1:03d}",
                    "timestamp": datetime.utcnow().isoformat(),
                    "signature": sig,
                    "related_logs": [],
                }
                new_issues.append(issue)

        if new_issues:
            self.issues.extend(new_issues)
            self._save_state()

        self.status = "ready"
        return new_issues

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
            "log_trend": self.log_trend,
            "rule_distribution": self.rule_distribution,
            "active_api_key_index": self.gemini.current,
        }

    async def get_metrics_text(self) -> str:
        return await self.metrics.render()

    # ------------------------------------------------------------------
    def ignore_issue(self, issue_id: str) -> None:
        """Remove an issue and persist the ignore list."""
        self.issues = [i for i in self.issues if i.get("id") != issue_id]
        self.ignored.add(issue_id)
        self._save_state()

    # ------------------------------------------------------------------
    def _update_metrics(self, logs: List[Dict[str, Any]]):
        """Update log trend and rule distribution metrics."""
        timestamp = datetime.utcnow().strftime("%H:%M")
        self.log_trend.append({"time": timestamp, "count": len(logs)})
        self.log_trend = self.log_trend[-60:]
        for entry in logs:
            rule = entry.get("rule", {})
            name = rule.get("description") or str(rule.get("id") or "unknown")
            self.rule_distribution[name] = self.rule_distribution.get(name, 0) + 1
