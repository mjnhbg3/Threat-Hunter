import asyncio
import time
from typing import List

import google.generativeai as genai

from threat_hunter.utils.logger import logger


class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.timestamp = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, tokens: float) -> bool:
        async with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.timestamp) * self.rate)
            self.timestamp = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait(self, tokens: float):
        while not await self.consume(tokens):
            await asyncio.sleep(0.1)


class Gemini:
    def __init__(self, api_keys: List[str]):
        self.api_keys = [k for k in api_keys if k]
        if not self.api_keys:
            raise ValueError("No Gemini API keys configured")
        self.current = 0
        self.buckets = {key: TokenBucket(10, 10) for key in self.api_keys}
        genai.configure(api_key=self.api_keys[self.current])

    def rotate(self):
        self.current = (self.current + 1) % len(self.api_keys)
        genai.configure(api_key=self.api_keys[self.current])
        logger.info("Switched to API key %d", self.current)

    async def generate(self, prompt: str, model: str = "gemini-pro", max_tokens: int = 1024) -> str:
        key = self.api_keys[self.current]
        bucket = self.buckets[key]
        await bucket.wait(1)
        try:
            model_obj = genai.GenerativeModel(model)
            resp = await asyncio.to_thread(model_obj.generate_content, prompt, generation_config={"max_output_tokens": max_tokens})
            return resp.text
        except Exception as e:
            logger.error("Gemini API error: %s", e)
            self.rotate()
            return ""
