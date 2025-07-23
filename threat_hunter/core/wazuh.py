
import httpx
from threat_hunter.utils.logger import logger

class WazuhAPI:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.auth = (username, password)
        self.client = httpx.AsyncClient(auth=self.auth, verify=False) # In production, use verify=True with proper certs

    async def get_alerts(self, time_range='1h'):
        try:
            response = await self.client.get(f"{self.base_url}/alerts?timeframe={time_range}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Error fetching Wazuh alerts: {e}")
            return None
