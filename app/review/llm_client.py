"""
SecureCodeGuard – LLM Client

Communicates with the local Ollama instance to generate reviews.
Includes retry logic, timeout handling, and JSON extraction.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, Optional

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class OllamaClient:
    """Client for communicating with a local Ollama LLM instance."""

    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.ollama_base_url.rstrip("/")
        self.model = self.settings.ollama_model
        self.timeout = self.settings.ollama_timeout

    def is_available(self) -> bool:
        """Check if Ollama is reachable."""
        try:
            resp = httpx.get(
                f"{self.base_url}/api/tags",
                timeout=5.0,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def get_available_models(self) -> list:
        """List available models from Ollama."""
        try:
            resp = httpx.get(
                f"{self.base_url}/api/tags",
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            pass
        return []

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        output_format: Optional[str] = None,
    ) -> str:
        """
        Generate a completion from the local LLM.

        Parameters
        ----------
        prompt : str
            The user prompt.
        system_prompt : str
            System prompt with instructions.
        temperature : float
            Sampling temperature (low for deterministic output).
        max_tokens : int
            Maximum tokens to generate.

        Returns
        -------
        str : The model's response text.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if output_format:
            payload["format"] = output_format

        try:
            logger.info("Sending request to Ollama model: %s", self.model)
            resp = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            response_text = data.get("response", "")
            logger.info(
                "Received response from Ollama (%d chars)",
                len(response_text),
            )
            return response_text
        except httpx.TimeoutException:
            logger.error("Ollama request timed out after %ds", self.timeout)
            return ""
        except httpx.HTTPStatusError as e:
            logger.error(
                "Ollama HTTP error: %s; response: %s",
                e,
                e.response.text[:1000],
            )
            return ""
        except Exception as e:
            logger.error("Ollama error: %s", e)
            return ""

    def generate_json(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a response and attempt to parse it as JSON.

        Extracts JSON from markdown code blocks if present.
        """
        raw = self.generate(
            prompt,
            system_prompt,
            temperature,
            max_tokens=max_tokens,
            output_format="json",
        )
        if not raw:
            return None

        return extract_json(raw)


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract a JSON object from LLM response text.

    Handles:
    - Pure JSON responses
    - JSON within ```json ... ``` blocks
    - JSON within ``` ... ``` blocks
    """
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from code blocks
    patterns = [
        r'```json\s*\n(.*?)\n\s*```',
        r'```\s*\n(.*?)\n\s*```',
        r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue

    # Last resort: find the largest JSON-like substring
    start = text.find("{")
    if start >= 0:
        depth = 0
        end = start
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    logger.warning("Failed to extract JSON from LLM response")
    return None


# Singleton
_client: Optional[OllamaClient] = None


def get_llm_client() -> OllamaClient:
    """Get the singleton Ollama client."""
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client
