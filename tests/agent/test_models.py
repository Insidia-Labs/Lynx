from collections.abc import Sequence
from typing import Any

import pytest
from langchain_anthropic import ChatAnthropic
from langchain_core.exceptions import (
    ModelAuthenticationError,
    ModelConnectionError,
    ModelError,
    ModelInvalidRequestError,
    ModelNotFoundError,
    ModelPermissionDeniedError,
    ModelRateLimitError,
    ModelTimeoutError,
)
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_openai import ChatOpenAI
from pydantic import Field

from lynx.agent import models
from lynx.agent.models import chat_model, check_tool_calling
from lynx.config import ModelSpec

CLAUDE = ModelSpec(provider="anthropic", name="claude-opus-5-5")
LOCAL = ModelSpec(provider="openai", name="qwen3.5", base_url="http://localhost:8000/v1")


class _Scripted(BaseChatModel):
    """Answers with one fixed reply, or raises one error; records how tools were bound."""

    reply: AIMessage = AIMessage(content="")
    error: ModelError | None = None
    bound: dict[str, Any] = Field(default_factory=dict)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages: list[BaseMessage], *args: Any, **kwargs: Any) -> ChatResult:
        if self.error is not None:
            raise self.error
        return ChatResult(generations=[ChatGeneration(message=self.reply)])

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> _Scripted:
        self.bound.update(tools=list(tools), **kwargs)
        return self


def _use(monkeypatch: pytest.MonkeyPatch, model: _Scripted) -> None:
    monkeypatch.setattr(models, "chat_model", lambda *_: model)


def _tool_call(name: str, args: dict[str, Any]) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": "call-1"}])


def test_a_model_that_makes_the_tool_call_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, _Scripted(reply=_tool_call("Confirm", {"word": "lynx"})))

    assert check_tool_calling(CLAUDE) is None


def test_the_tool_call_is_requested_not_forced(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _Scripted(reply=_tool_call("Confirm", {"word": "lynx"}))
    _use(monkeypatch, model)

    check_tool_calling(CLAUDE)

    # Current Claude models reject a forced tool call (tool_choice any or tool).
    assert model.bound == {"tools": [models.Confirm]}


@pytest.mark.parametrize(
    "reply",
    [AIMessage(content="Sure, lynx."), _tool_call("Something", {"word": "lynx"})],
)
def test_a_model_that_answers_without_the_tool_call_fails(
    monkeypatch: pytest.MonkeyPatch, reply: AIMessage
) -> None:
    _use(monkeypatch, _Scripted(reply=reply))

    problem = check_tool_calling(CLAUDE)

    assert problem is not None
    assert "needs a model with tool calling" in problem


def test_a_tool_call_that_breaks_the_schema_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, _Scripted(reply=_tool_call("Confirm", {"words": ["lynx"]})))

    problem = check_tool_calling(CLAUDE)

    assert problem is not None
    assert "didn't match the tool's schema" in problem


@pytest.mark.parametrize(
    ("error", "spec", "expected"),
    [
        (ModelAuthenticationError("401"), CLAUDE, "rejected the key (check ANTHROPIC_API_KEY)"),
        (ModelAuthenticationError("401"), LOCAL, "rejected the key (check OPENAI_API_KEY)"),
        (ModelPermissionDeniedError("403"), CLAUDE, "isn't allowed to use this model"),
        (ModelNotFoundError("404"), CLAUDE, "no model by this name"),
        (ModelRateLimitError("429"), CLAUDE, "rate limited"),
        (ModelTimeoutError("slow"), CLAUDE, "no answer within 60 seconds"),
        (ModelConnectionError("down"), LOCAL, "couldn't reach the API"),
        (ModelInvalidRequestError("bad request"), CLAUDE, "API returned an error: bad request"),
    ],
)
def test_api_errors_are_explained(
    monkeypatch: pytest.MonkeyPatch, error: ModelError, spec: ModelSpec, expected: str
) -> None:
    _use(monkeypatch, _Scripted(error=error))

    problem = check_tool_calling(spec)

    assert problem is not None
    assert expected in problem


def test_an_openai_compatible_model_without_a_key_says_which_variable_to_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("OPENAI_API_KEY", "OPENAI_ADMIN_KEY"):
        monkeypatch.delenv(name, raising=False)

    problem = check_tool_calling(LOCAL)

    assert problem is not None
    assert "OPENAI_API_KEY" in problem


def test_an_anthropic_spec_builds_chat_anthropic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_URL", raising=False)

    model = chat_model(CLAUDE, max_tokens=512, timeout=30)

    assert isinstance(model, ChatAnthropic)
    assert (model.model, model.max_tokens, model.default_request_timeout) == (
        "claude-opus-5-5",
        512,
        30,
    )
    assert model.anthropic_api_url == "https://api.anthropic.com"


def test_an_openai_spec_builds_chat_openai_on_its_base_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "placeholder")

    model = chat_model(LOCAL, max_tokens=512, timeout=30)

    assert isinstance(model, ChatOpenAI)
    assert (model.model_name, model.openai_api_base) == ("qwen3.5", "http://localhost:8000/v1")
    assert (model.max_tokens, model.request_timeout) == (512, 30)
