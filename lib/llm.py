"""LLM access with retry/backoff and provider fallback. Owned by P1."""
from __future__ import annotations

import json
import os
import random
import re
import time
from typing import Type, TypeVar

from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()

T = TypeVar("T", bound=BaseModel)

# Model names change on free tiers; override via .env if one is retired.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


class LLMError(RuntimeError):
    pass


def _gemini(temperature: float):
    from langchain_google_genai import ChatGoogleGenerativeAI
    return ChatGoogleGenerativeAI(
        model=GEMINI_MODEL,
        google_api_key=os.getenv("GEMINI_API_KEY"),
        temperature=temperature,
    )


def _groq(temperature: float):
    from langchain_groq import ChatGroq
    return ChatGroq(
        model=GROQ_MODEL,
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=temperature,
    )


# Defined AFTER the factory functions, and after the env is loaded.
LLM_ORDER = [p.strip() for p in os.getenv("LLM_ORDER", "gemini,groq").split(",")]
_FACTORIES = {"gemini": _gemini, "groq": _groq}


def _json_mode(factory, system: str, user: str, schema: Type[T], temperature: float) -> T:
    """Fallback when tool calling fails: ask for raw JSON and validate it."""
    prompt = (system + "\n\nRespond with ONLY one JSON object matching this schema. "
              "No prose, no markdown.\n" + json.dumps(schema.model_json_schema()))
    msg = factory(temperature).invoke([("system", prompt), ("human", user)])
    text = msg.content if isinstance(msg.content, str) else str(msg.content)
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise ValueError("no JSON object in model reply")
    return schema.model_validate_json(match.group(0))


def ask(system: str, user: str, schema: Type[T],
        temperature: float = 0.0, retries: int = 3) -> T:
    """Call an LLM and return a validated Pydantic object.

    Tries providers in LLM_ORDER. Each gets `retries` attempts with
    exponential backoff. Daily-quota errors skip straight to the next
    provider, and tool-call failures retry in plain JSON mode.
    """
    last_err: Exception | None = None
    for name in LLM_ORDER:
        factory = _FACTORIES[name]
        use_json_mode = False
        for attempt in range(retries):
            try:
                if use_json_mode:
                    return _json_mode(factory, system, user, schema, temperature)
                return (factory(temperature).with_structured_output(schema)
                        .invoke([("system", system), ("human", user)]))
            except Exception as e:
                last_err = e
                msg = str(e)
                print(f"[llm debug] {name} attempt {attempt + 1} failed: {type(e).__name__}")
                if "PerDay" in msg:                      # daily quota gone: don't retry
                    break
                if "tool_use_failed" in msg or "did not call a tool" in msg:
                    use_json_mode = True                  # retry in JSON mode
                    continue
                time.sleep(min(2 ** attempt + random.random(), 20))
    raise LLMError(f"All LLM providers failed: {last_err}")