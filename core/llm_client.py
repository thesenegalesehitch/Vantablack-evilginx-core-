import json
import logging
from typing import Any, Dict

import httpx

from .config import settings

logger = logging.getLogger("LLMClient")

async def generate_text(prompt: str, model: str | None = None) -> str:
    """
    Generates text using a local LLM via Ollama.

    Args:
        prompt: The input prompt for the model.
        model: The name of the Ollama model to use. Defaults to settings.DEFAULT_LLM_MODEL.

    Returns:
        The generated text, or an error message.
    """
    target_model = model or settings.DEFAULT_LLM_MODEL
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            payload = {
                "model": target_model,
                "prompt": prompt,
                "stream": False  # We want the full response at once
            }
            response = await client.post(settings.OLLAMA_API_URL, json=payload)
            response.raise_for_status()

            response_data = response.json()
            return response_data.get("response", "").strip()

    except httpx.ConnectError:
        error_msg = "LLM connection failed. Is the Ollama server running?"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"An error occurred while generating text: {e}"
        logger.error(error_msg)
        return error_msg
