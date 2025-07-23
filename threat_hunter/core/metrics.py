import asyncio
from collections import defaultdict


class MetricsCollector:
    """Simple metrics collector for Prometheus style metrics"""
    def __init__(self):
        self.gemini_requests = defaultdict(int)
        self.gemini_tokens = defaultdict(lambda: defaultdict(int))
        self.gemini_429 = defaultdict(int)
        self.worker_cycle_seconds = 0.0
        self.lock = asyncio.Lock()

    async def inc_requests(self, model: str):
        async with self.lock:
            self.gemini_requests[model] += 1

    async def add_tokens(self, model: str, direction: str, tokens: int):
        async with self.lock:
            self.gemini_tokens[model][direction] += tokens

    async def increment_429s(self, model: str):
        async with self.lock:
            self.gemini_429[model] += 1

    async def set_cycle_time(self, seconds: float):
        async with self.lock:
            self.worker_cycle_seconds = seconds

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
            for model, value in self.gemini_429.items():
                lines.append(
                    f"gemini_429_total{{model=\"{model}\"}} {value}"
                )
            lines.append(f"worker_cycle_seconds {self.worker_cycle_seconds}")
            return "\n".join(lines) + "\n"
