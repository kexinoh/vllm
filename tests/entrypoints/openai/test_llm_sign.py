# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from __future__ import annotations

import builtins
import sys
from types import ModuleType

import pytest

from vllm import envs
from vllm.entrypoints.openai import llm_sign
from vllm.entrypoints.openai.chat_completion.protocol import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionResponseChoice,
    ChatMessage,
)
from vllm.entrypoints.openai.engine.protocol import UsageInfo


@pytest.fixture(autouse=True)
def reset_llm_sign(monkeypatch: pytest.MonkeyPatch):
    llm_sign.clear_cached_signer()
    envs.disable_envs_cache()
    monkeypatch.delenv("VLLM_LLM_SIGN_ENABLED", raising=False)
    monkeypatch.delenv("VLLM_LLM_SIGN_CERTFILE", raising=False)
    monkeypatch.delenv("VLLM_LLM_SIGN_KEYFILE", raising=False)
    yield
    llm_sign.clear_cached_signer()
    envs.disable_envs_cache()


def test_llm_sign_is_disabled_by_default():
    request = _request()
    response = _response()

    assert llm_sign.maybe_sign_chat_completion(request, response) is response
    assert "llm_sign" not in response.model_dump()
    # When disabled the response must serialize byte-identically to a vanilla
    # vLLM response: the ``llm_sign`` key must not appear at all (as opposed
    # to appearing with a null value), so unsigned deployments stay
    # byte-compatible with upstream vLLM.
    assert "llm_sign" not in response.model_dump_json()


def test_llm_sign_filters_vllm_only_request_fields(monkeypatch: pytest.MonkeyPatch):
    """vLLM-only request knobs (e.g. ``min_tokens``) must not leak into the
    signed payload, otherwise the strict ``openai.chat-completions.input.v1``
    profile rejects the artifact with ``unknown fields``.
    """
    monkeypatch.setenv("VLLM_LLM_SIGN_ENABLED", "1")
    monkeypatch.setenv("VLLM_LLM_SIGN_CERTFILE", "cert.pem")
    monkeypatch.setenv("VLLM_LLM_SIGN_KEYFILE", "key.pem")

    captured: list[dict] = []
    _install_fake_llm_sign(monkeypatch, captured)

    # A request that includes a vLLM-only knob plus a standard one
    request = ChatCompletionRequest(
        model="test-model",
        messages=[{"role": "user", "content": "ping"}],
        min_tokens=3,  # vLLM extension
        temperature=0.0,  # OpenAI standard
    )
    llm_sign.maybe_sign_chat_completion(request, _response())

    signed_request = captured[1]["request"]
    assert "model" in signed_request
    assert "messages" in signed_request
    assert "temperature" in signed_request
    # vLLM-only knobs filtered out
    assert "min_tokens" not in signed_request


def test_llm_sign_filters_vllm_only_response_fields(monkeypatch: pytest.MonkeyPatch):
    """vLLM-only response fields (``prompt_logprobs``, ``prompt_token_ids``,
    ``kv_transfer_params``) must not leak into the signed payload, otherwise
    a verifier re-canonicalizing the HTTP body fails with ``unknown fields``.
    """
    monkeypatch.setenv("VLLM_LLM_SIGN_ENABLED", "1")
    monkeypatch.setenv("VLLM_LLM_SIGN_CERTFILE", "cert.pem")
    monkeypatch.setenv("VLLM_LLM_SIGN_KEYFILE", "key.pem")

    captured: list[dict] = []
    _install_fake_llm_sign(monkeypatch, captured)

    response = _response()
    response.prompt_logprobs = [None]
    response.prompt_token_ids = [1, 2, 3]
    response.kv_transfer_params = {"foo": "bar"}

    llm_sign.maybe_sign_chat_completion(_request(), response)

    signed_response = captured[1]["response"]
    assert "choices" in signed_response
    assert "model" in signed_response
    # vLLM-only response fields filtered out
    assert "prompt_logprobs" not in signed_response
    assert "prompt_token_ids" not in signed_response
    assert "kv_transfer_params" not in signed_response
    assert "llm_sign" not in signed_response


def _install_fake_llm_sign(
    monkeypatch: pytest.MonkeyPatch,
    captured: list[dict],
) -> None:
    """Install a fake ``llm_sign`` package so tests don't need cryptography."""

    fake_pkg = ModuleType("llm_sign")
    fake_server = ModuleType("llm_sign.server")

    _REQUEST_ALLOWED = {
        "messages",
        "model",
        "temperature",
        "top_p",
        "stop",
        "max_tokens",
        "tools",
        "tool_choice",
        "n",
        "stream",
        "user",
        "metadata",
    }
    _RESPONSE_ALLOWED = {
        "choices",
        "model",
        "response_format",
        "created",
        "id",
        "object",
        "usage",
        "system_fingerprint",
    }

    def fake_project_openai_chat_request(payload):
        return {k: v for k, v in payload.items() if k in _REQUEST_ALLOWED}

    def fake_project_openai_chat_response(payload):
        return {k: v for k, v in payload.items() if k in _RESPONSE_ALLOWED}

    # Populate the fake ``llm_sign`` package. mypy types ``fake_pkg`` as the
    # bare ``types.ModuleType`` stub (which of course knows nothing about
    # ``llm_sign``'s public API) and treats ``setattr(mod, "literal", ...)``
    # as an attribute-existence check against that stub, so we silence it
    # explicitly rather than dodging the check.
    setattr(  # type: ignore[attr-defined]
        fake_pkg, "project_openai_chat_request", fake_project_openai_chat_request
    )
    setattr(  # type: ignore[attr-defined]
        fake_pkg, "project_openai_chat_response", fake_project_openai_chat_response
    )

    class FakeCredential:
        @classmethod
        def from_files(cls, **kwargs):
            captured.append(kwargs)
            return cls()

        def signer(self):
            return "signer"

        def certificate_chain_pem(self):
            return ["cert-chain"]

    def fake_sign_openai_chat_turn(**kwargs):
        captured.append(kwargs)
        return {"schema": "llm-sign.artifact.v1"}

    def fake_attach(envelope, *, artifact, credential=None, certificate_chain_pem=None):
        envelope["llm_sign"] = {"artifact": dict(artifact)}
        chain = certificate_chain_pem
        if chain is None and credential is not None:
            chain = credential.certificate_chain_pem()
        if chain is not None:
            envelope["llm_sign"]["certificate_chain"] = list(chain)
        captured.append({"attached": envelope["llm_sign"]})
        return envelope

    # Same rationale as above: mypy only sees ``fake_server`` as a generic
    # ``types.ModuleType`` and flags these literal attribute writes.
    setattr(fake_server, "TLSCertificateCredential", FakeCredential)  # type: ignore[attr-defined]
    setattr(fake_server, "sign_openai_chat_turn", fake_sign_openai_chat_turn)  # type: ignore[attr-defined]
    setattr(  # type: ignore[attr-defined]
        fake_server, "attach_signed_artifact_to_openai_response", fake_attach
    )

    monkeypatch.setitem(sys.modules, "llm_sign", fake_pkg)
    monkeypatch.setitem(sys.modules, "llm_sign.server", fake_server)


def test_llm_sign_attaches_artifact_when_enabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VLLM_LLM_SIGN_ENABLED", "1")
    monkeypatch.setenv("VLLM_LLM_SIGN_CERTFILE", "cert.pem")
    monkeypatch.setenv("VLLM_LLM_SIGN_KEYFILE", "key.pem")

    calls: list[dict] = []
    _install_fake_llm_sign(monkeypatch, calls)

    response = llm_sign.maybe_sign_chat_completion(_request(), _response())

    assert response.llm_sign == {
        "artifact": {"schema": "llm-sign.artifact.v1"},
        "certificate_chain": ["cert-chain"],
    }
    # The issuer (host name) is derived from the certificate by llm_sign;
    # vLLM forwards only the cert and key paths.
    assert calls[0] == {
        "ssl_certfile": "cert.pem",
        "ssl_keyfile": "key.pem",
    }
    assert calls[1]["request"]["model"] == "test-model"
    assert calls[1]["response"]["choices"][0]["message"]["content"] == "pong"
    assert calls[1]["signer"] == "signer"
    # The envelope was produced by llm_sign's official helper, not by
    # vLLM inlining the dict layout.
    assert calls[-1] == {
        "attached": {
            "artifact": {"schema": "llm-sign.artifact.v1"},
            "certificate_chain": ["cert-chain"],
        }
    }


def test_llm_sign_requires_cert_and_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VLLM_LLM_SIGN_ENABLED", "1")

    with pytest.raises(ValueError, match="VLLM_LLM_SIGN_CERTFILE"):
        llm_sign.maybe_sign_chat_completion(_request(), _response())


def test_llm_sign_import_is_optional_until_enabled(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("VLLM_LLM_SIGN_ENABLED", "1")
    monkeypatch.setenv("VLLM_LLM_SIGN_CERTFILE", "cert.pem")
    monkeypatch.setenv("VLLM_LLM_SIGN_KEYFILE", "key.pem")
    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "llm_sign.server":
            raise ImportError("missing llm_sign")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ImportError, match="llm_sign must be installed"):
        llm_sign.maybe_sign_chat_completion(_request(), _response())


def _request() -> ChatCompletionRequest:
    return ChatCompletionRequest(
        model="test-model",
        messages=[{"role": "user", "content": "ping"}],
    )


def _response() -> ChatCompletionResponse:
    return ChatCompletionResponse(
        model="test-model",
        choices=[
            ChatCompletionResponseChoice(
                index=0,
                message=ChatMessage(role="assistant", content="pong"),
            )
        ],
        usage=UsageInfo(prompt_tokens=1, completion_tokens=1, total_tokens=2),
    )
