"""LLM client for OpenAI-compatible chat completion endpoints."""
from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from .config import MAX_REQUESTS_PER_MINUTE, DEFAULT_RATE_LIMIT
from .rate_limit import llm_limiter


class LLMError(Exception):
    pass


def normalize_base_url(url: str) -> str:
    """Accept a base URL or a full chat-completions URL and return the endpoint."""
    url = (url or "").strip().rstrip("/")
    if not url:
        raise LLMError("LLM base URL is not configured")
    if url.endswith("/chat/completions"):
        return url
    if url.endswith("/v1"):
        return url + "/chat/completions"
    return url + "/v1/chat/completions"


class LLMClient:
    def __init__(self, *, api_key: str, base_url: str, model: str,
                 rate_limit: int = 60, timeout: float = 120.0) -> None:
        if not api_key:
            raise LLMError("LLM API key is not configured")
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        llm_limiter.set_limit(rate_limit)

    async def chat(self, messages: list[dict], tools: list[dict] | None = None,
                   temperature: float = 0.3) -> dict:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        waited = await asyncio.to_thread(llm_limiter.acquire)
        if waited > 0.5:
            await asyncio.sleep(0)  # keep loop cooperative

        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(self.base_url, headers=headers, json=payload)
                if resp.status_code == 429:
                    retry_after = float(resp.headers.get("retry-after", 5) or 5)
                    await asyncio.sleep(min(retry_after, 30))
                    last_exc = LLMError("Rate limited by upstream provider (429)")
                    continue
                if resp.status_code >= 400:
                    detail = resp.text[:500]
                    raise LLMError(f"LLM request failed ({resp.status_code}): {detail}")
                return resp.json()
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last_exc = exc
                await asyncio.sleep(1.5 * (attempt + 1))
        raise LLMError(f"LLM request failed after retries: {last_exc}")


def parse_response(data: dict) -> dict:
    """Extract a normalized assistant message from a chat completion response."""
    try:
        choice = data["choices"][0]
        msg = choice.get("message", {}) or {}
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"Malformed LLM response: {exc}") from exc

    tool_calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {}) or {}
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except json.JSONDecodeError:
            args = {"_raw": raw_args}
        tool_calls.append({
            "id": tc.get("id", ""),
            "name": fn.get("name", ""),
            "arguments": args,
        })

    return {
        "content": msg.get("content") or "",
        "tool_calls": tool_calls,
        "finish_reason": choice.get("finish_reason"),
        "usage": data.get("usage", {}),
    }


def get_runtime_config() -> dict:
    """Read LLM settings from the encrypted settings store."""
    from . import database as db
    from .config import DEFAULT_RATE_LIMIT
    cfg = db.get_secret_setting("llm_config") or {}
    return {
        "api_key": cfg.get("api_key", ""),
        "base_url": cfg.get("base_url", "https://api.openai.com/v1"),
        "model": cfg.get("model", "gpt-4o-mini"),
        "rate_limit": int(cfg.get("rate_limit", DEFAULT_RATE_LIMIT) or DEFAULT_RATE_LIMIT),
        "temperature": float(cfg.get("temperature", 0.3) or 0.3),
        "max_steps": int(cfg.get("max_steps", 8) or 8),
    }


def is_configured() -> bool:
    cfg = get_runtime_config()
    return bool(cfg["api_key"] and cfg["base_url"] and cfg["model"])


def make_client(cfg: dict | None = None) -> LLMClient:
    cfg = cfg or get_runtime_config()
    return LLMClient(
        api_key=cfg["api_key"],
        base_url=normalize_base_url(cfg["base_url"]),
        model=cfg["model"],
        rate_limit=cfg["rate_limit"],
    )


def clamp_rate_limit(value: int) -> int:
    return max(1, min(int(value), MAX_REQUESTS_PER_MINUTE))
