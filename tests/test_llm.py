import pytest
from pydantic import BaseModel

from lib import llm


class Out(BaseModel):
    answer: str


class FakeLLM:
    def __init__(self, fail=False):
        self.fail = fail

    def with_structured_output(self, schema):
        return self

    def invoke(self, messages):
        if self.fail:
            raise RuntimeError("rate limited")
        return Out(answer="ok")


def test_ask_returns_structured_output(monkeypatch):
    monkeypatch.setattr(llm, "_gemini", lambda t: FakeLLM())
    assert llm.ask("sys", "user", Out).answer == "ok"


def test_falls_back_to_groq_when_gemini_fails(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    monkeypatch.setattr(llm, "_gemini", lambda t: FakeLLM(fail=True))
    monkeypatch.setattr(llm, "_groq", lambda t: FakeLLM())
    assert llm.ask("sys", "user", Out).answer == "ok"


def test_raises_when_all_providers_fail(monkeypatch):
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    monkeypatch.setattr(llm, "_gemini", lambda t: FakeLLM(fail=True))
    monkeypatch.setattr(llm, "_groq", lambda t: FakeLLM(fail=True))
    with pytest.raises(llm.LLMError):
        llm.ask("sys", "user", Out)