import httpx
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("LLMClient")

OLLAMA_API_URL = "http://localhost:11434/api/generate"

async def generate_text(prompt: str, model: str = "llama3") -> str:
    """
    Generates text using a local LLM via Ollama.

    Args:
        prompt: The input prompt for the model.
        model: The name of the Ollama model to use (e.g., 'llama3', 'mistral').

    Returns:
        The generated text, or an error message.
    """
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False  # We want the full response at once
            }
            response = await client.post(OLLAMA_API_URL, json=payload)
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
