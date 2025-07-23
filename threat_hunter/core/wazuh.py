import json
import os
from typing import List, Dict, Any

import httpx

from threat_hunter.utils.logger import logger


class WazuhAPI:
    def __init__(self, base_url: str, username: str, password: str, log_file: str = "/var/ossec/logs/alerts/alerts.json"):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.client = httpx.AsyncClient(auth=self.auth, verify=False)
        self.log_file = log_file
        self.position_file = self.log_file + ".pos"

    async def get_alerts(self, timeframe: str = "1h") -> List[Dict[str, Any]]:
        url = f"{self.base_url}/alerts?timeframe={timeframe}"
        try:
            resp = await self.client.get(url)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as e:
            logger.error("Wazuh API error: %s", e)
            return []

    def _read_position(self) -> int:
        if os.path.exists(self.position_file):
            with open(self.position_file, "r") as f:
                try:
                    return int(f.read())
                except ValueError:
                    return 0
        return 0

    def _write_position(self, pos: int) -> None:
        with open(self.position_file, "w") as f:
            f.write(str(pos))

    async def read_new_logs(self, batch_size: int = 1000) -> List[Dict[str, Any]]:
        if not os.path.exists(self.log_file):
            return []
        logs: List[Dict[str, Any]] = []
        pos = self._read_position()
        with open(self.log_file, "r", errors="ignore") as f:
            f.seek(pos)
            for _ in range(batch_size):
                line = f.readline()
                if not line:
                    break
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            self._write_position(f.tell())
        logger.info("Read %d new logs", len(logs))
        return logs
