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


def _use(monkeypatch, **factories):
    monkeypatch.setattr(llm, "_FACTORIES", factories)
    monkeypatch.setattr(llm, "LLM_ORDER", list(factories))
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)


def test_ask_returns_structured_output(monkeypatch):
    _use(monkeypatch, gemini=lambda t: FakeLLM())
    assert llm.ask("sys", "user", Out).answer == "ok"


def test_falls_back_to_second_provider_when_first_fails(monkeypatch):
    _use(monkeypatch, gemini=lambda t: FakeLLM(fail=True), groq=lambda t: FakeLLM())
    assert llm.ask("sys", "user", Out).answer == "ok"


def test_raises_when_all_providers_fail(monkeypatch):
    _use(monkeypatch, gemini=lambda t: FakeLLM(fail=True), groq=lambda t: FakeLLM(fail=True))
    with pytest.raises(llm.LLMError):
        llm.ask("sys", "user", Out)


def test_daily_quota_skips_retries(monkeypatch):
    calls = {"n": 0}

    class Quota:
        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            calls["n"] += 1
            raise RuntimeError("429 GenerateRequestsPerDayPerProjectPerModel")

    _use(monkeypatch, gemini=lambda t: Quota(), groq=lambda t: FakeLLM())
    assert llm.ask("sys", "user", Out).answer == "ok"
    assert calls["n"] == 1          # gave up on Gemini after one try


def test_json_mode_fallback_on_tool_use_failure(monkeypatch):
    class ToolFail:
        def with_structured_output(self, schema):
            raise RuntimeError("tool_use_failed: model did not call a tool")

        def invoke(self, messages):
            class R:
                content = '{"answer": "ok"}'
            return R()

    _use(monkeypatch, groq=lambda t: ToolFail())
    assert llm.ask("sys", "user", Out).answer == "ok"