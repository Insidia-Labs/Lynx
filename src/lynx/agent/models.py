"""Chat models, through LangChain: Anthropic, or any OpenAI-compatible API.

Every role needs tool calling, so `check_tool_calling` asks a model for one small
tool call before anything relies on it. Keys come from the providers' own
environment variables, which the SDKs read themselves.
"""

import openai
from langchain_anthropic import ChatAnthropic
from langchain_core.exceptions import (
    ModelAuthenticationError,
    ModelConnectionError,
    ModelError,
    ModelNotFoundError,
    ModelPermissionDeniedError,
    ModelRateLimitError,
    ModelTimeoutError,
)
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ValidationError

from lynx.config import MODEL_CHECK_MAX_TOKENS, MODEL_CHECK_TIMEOUT, ModelSpec

_KEY_VARIABLES = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

_CHECK_PROMPT = (
    'This is a setup check. Call the Confirm tool with word set to "lynx". Don\'t reply with text.'
)
_PROBLEMS: tuple[tuple[type[ModelError], str], ...] = (
    (ModelAuthenticationError, "the API rejected the key (check {key})"),
    (ModelPermissionDeniedError, "the key isn't allowed to use this model"),
    (ModelNotFoundError, "the API has no model by this name"),
    (ModelRateLimitError, "rate limited; try again in a minute"),
    (ModelTimeoutError, "no answer within {timeout} seconds"),
    (ModelConnectionError, "couldn't reach the API"),
)


class Confirm(BaseModel):
    """Confirm that you can call tools."""

    word: str


def chat_model(spec: ModelSpec, max_tokens: int, timeout: float) -> BaseChatModel:
    # Field names rather than their aliases (base_url, timeout), so mypy can check them.
    if spec.provider == "anthropic":
        return ChatAnthropic(
            model=spec.name,
            anthropic_api_url=spec.base_url,
            max_tokens=max_tokens,
            default_request_timeout=timeout,
        )
    return ChatOpenAI(
        model_name=spec.name,
        openai_api_base=spec.base_url,
        max_tokens=max_tokens,
        request_timeout=timeout,
    )


def check_tool_calling(spec: ModelSpec) -> str | None:
    """None when the model makes the tool call it's asked for, otherwise the problem.

    Tool choice is left on auto: current Claude models reject a forced tool call.
    """
    try:
        model = chat_model(spec, MODEL_CHECK_MAX_TOKENS, MODEL_CHECK_TIMEOUT)
        reply = model.bind_tools([Confirm]).invoke(_CHECK_PROMPT)
    except ModelError as error:
        return _problem(error, spec)
    except openai.OpenAIError as error:  # raised before any request, e.g. no key set
        return str(error)
    calls = reply.tool_calls if isinstance(reply, AIMessage) else []
    if not calls or calls[0]["name"] != Confirm.__name__:
        return "it answered without the tool call; Lynx needs a model with tool calling"
    try:
        Confirm.model_validate(calls[0]["args"])
    except ValidationError:
        return f"its tool call didn't match the tool's schema: {calls[0]['args']}"
    return None


def _problem(error: ModelError, spec: ModelSpec) -> str:
    for kind, message in _PROBLEMS:
        if isinstance(error, kind):
            return message.format(key=_KEY_VARIABLES[spec.provider], timeout=MODEL_CHECK_TIMEOUT)
    return f"the API returned an error: {error}"
