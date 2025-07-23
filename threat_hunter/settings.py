
import os
from functools import lru_cache
from threat_hunter.core.threat_hunter_core import ThreatHunterCore
from threat_hunter.core.wazuh import WazuhAPI

@lru_cache()
def get_threat_hunter_core():
    api_keys = os.environ.get("GEMINI_API_KEYS", "").split(",")
    wazuh_base_url = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
    wazuh_user = os.environ.get("WAZUH_API_USER", "wazuh")
    wazuh_password = os.environ.get("WAZUH_API_PASSWORD", "wazuh")

    wazuh_api = WazuhAPI(wazuh_base_url, wazuh_user, wazuh_password)
    return ThreatHunterCore(api_keys=api_keys, wazuh_api=wazuh_api)
