import asyncio
import time
from typing import Dict, List

from threat_hunter.core.metrics import MetricsCollector

import google.generativeai as genai

from threat_hunter.utils.logger import logger


MODEL_QUOTA: Dict[str, tuple[int, int]] = {
    "pro": (5, 250_000),
    "flash": (10, 250_000),
    "flash-lite": (15, 250_000),
}

class TokenBucket:
    """Simple token bucket for rate limiting."""

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: int) -> bool:
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait_for_tokens(self, tokens: int) -> None:
        while not await self.consume(tokens):
            needed = tokens - self.tokens
            wait_time = needed / self.refill_rate
            await asyncio.sleep(wait_time + 0.1)


class Gemini:
    def __init__(self, api_keys: List[str], metrics: MetricsCollector | None = None) -> None:
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("No Gemini API keys configured")
        self.current = 0
        self.rpm_buckets: Dict[str, TokenBucket] = {}
        self.tpm_buckets: Dict[str, TokenBucket] = {}
        self.failures: Dict[str, int] = {k: 0 for k in self.api_keys}
        genai.configure(api_key=self.api_keys[self.current])
        self.metrics = metrics or MetricsCollector()

    def rotate(self):
        old = self.current
        self.current = (self.current + 1) % len(self.api_keys)
        genai.configure(api_key=self.api_keys[self.current])
        self.failures[self.api_keys[old]] = 0
        logger.info("Switched to API key %d", self.current)

    @property
    def active_key_index(self) -> int:
        return self.current

    def _get_model_family(self, model: str) -> str:
        model = model.lower()
        if "pro" in model:
            return "pro"
        if "lite" in model:
            return "flash-lite"
        return "flash"

    def count_tokens_local(self, text: str, model: str) -> int:
        """Count tokens using the official method with fallback."""
        try:
            m = genai.GenerativeModel(model)
            result = m.count_tokens(text)
            return result.total_tokens
        except Exception as exc:  # pragma: no cover - best effort
            logger.warning("Token counting failed for %s: %s", model, exc)
            char_count = len(text.encode("utf-8"))
            if text.strip().startswith("{") or '"' in text[:100]:
                est = char_count // 3
            else:
                est = char_count // 4
            return max(1, est)

    async def generate(
        self,
        prompt: str,
        model: str = "gemini-pro",
        max_tokens: int = 1024,
    ) -> str:
        model_family = self._get_model_family(model)
        rpm_limit, tpm_limit = MODEL_QUOTA.get(model_family, (10, 250_000))

        key = self.api_keys[self.current]
        rpm_bucket = self.rpm_buckets.setdefault(
            key, TokenBucket(rpm_limit, rpm_limit / 60.0)
        )
        tpm_bucket = self.tpm_buckets.setdefault(
            key, TokenBucket(tpm_limit, tpm_limit / 60.0)
        )

        input_tokens = self.count_tokens_local(prompt, model)
        await rpm_bucket.wait_for_tokens(1)
        await tpm_bucket.wait_for_tokens(input_tokens + max_tokens)

        try:
            model_obj = genai.GenerativeModel(model)
            resp = await asyncio.to_thread(
                model_obj.generate_content,
                prompt,
                generation_config={"max_output_tokens": max_tokens},
            )
            await self.metrics.inc_requests(model)
            await self.metrics.add_tokens(model, "in", input_tokens)
            await self.metrics.add_tokens(
                model, "out", self.count_tokens_local(resp.text, model)
            )
            self.failures[key] = 0
            return resp.text
        except Exception as e:
            if "429" in str(e):
                await self.metrics.increment_429s(model)
            logger.error("Gemini API error: %s", e)
            if "429" in str(e):
                self.failures[key] += 1
                if self.failures[key] >= 3:
                    self.rotate()
            else:
                self.rotate()
            return ""
