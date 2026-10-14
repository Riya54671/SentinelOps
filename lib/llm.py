"""LLM access with retry/backoff and provider fallback. Owned by P1."""
from __future__ import annotations

import os
import random
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


def ask(system: str, user: str, schema: Type[T],
        temperature: float = 0.0, retries: int = 3) -> T:
    """Call an LLM and return a validated Pydantic object.

    Tries Gemini first, then Groq. Each provider gets `retries` attempts
    with exponential backoff (handles free-tier rate limits).
    """
    last_err: Exception | None = None
    for name, factory in (("gemini", _gemini), ("groq", _groq)):
        try:
            llm = factory(temperature).with_structured_output(schema)
        except Exception as e:  # missing key / package
            last_err = e
            continue
        for attempt in range(retries):
            try:
                return llm.invoke([("system", system), ("human", user)])
            except Exception as e:
                last_err = e
                print(f"[llm debug] {name} attempt {attempt + 1} failed: "
                      f"{type(e).__name__}: {e}")
                time.sleep(min(2 ** attempt + random.random(), 20))
    raise LLMError(f"All LLM providers failed: {last_err}")