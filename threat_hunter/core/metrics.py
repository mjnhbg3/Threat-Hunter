import asyncio
from collections import defaultdict


class MetricsCollector:
    """Simple metrics collector for Prometheus style metrics"""
    def __init__(self):
        self.gemini_requests = defaultdict(int)
        self.gemini_tokens = defaultdict(lambda: defaultdict(int))
        self.lock = asyncio.Lock()

    async def inc_requests(self, model: str):
        async with self.lock:
            self.gemini_requests[model] += 1

    async def add_tokens(self, model: str, direction: str, tokens: int):
        async with self.lock:
            self.gemini_tokens[model][direction] += tokens

    async def render(self) -> str:
        async with self.lock:
            lines = []
            for model, count in self.gemini_requests.items():
                lines.append(
                    f"gemini_requests_total{{model=\"{model}\"}} {count}"
                )
            for model, data in self.gemini_tokens.items():
                for direction, value in data.items():
                    lines.append(
                        f"gemini_tokens_total{{model=\"{model}\",direction=\"{direction}\"}} {value}"
                    )
            return "\n".join(lines) + "\n"
