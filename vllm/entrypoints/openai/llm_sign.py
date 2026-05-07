# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: Copyright contributors to the vLLM project

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import vllm.envs as envs
from vllm.entrypoints.openai.chat_completion.protocol import ChatCompletionResponse


def maybe_sign_chat_completion(
    request: Any,
    response: Any,
) -> Any:
    """Attach llm_sign metadata to a Chat Completions response when enabled.

    When ``VLLM_LLM_SIGN_ENABLED=1`` is set and the response is a regular
    :class:`ChatCompletionResponse`, this helper:

    1. Projects the request and response to the OpenAI Chat Completions
       v1 canonical schemas (vLLM-only knobs such as ``min_tokens``,
       ``prompt_logprobs`` are dropped; they are not covered by the
       signing profile).
    2. Signs the projected turn with the TLS private key loaded from
       ``VLLM_LLM_SIGN_CERTFILE`` / ``VLLM_LLM_SIGN_KEYFILE``.
    3. Attaches ``{"artifact": ..., "certificate_chain": [...pem...]}``
       under the ``llm_sign`` field of the response envelope, using the
       official :func:`llm_sign.server.attach_signed_artifact_to_openai_response`
       helper so the wire format stays in lockstep with ``llm_sign``'s
       spec.

    Downstream clients verify the response with
    :func:`llm_sign.client.verify_openai_response`, which authenticates
    the embedded certificate chain under the standard TLS / X.509
    server-certificate validation rules (using the system TLS trust
    store by default) and then verifies the transcript under the
    validated leaf public key.
    """

    if not envs.VLLM_LLM_SIGN_ENABLED or not isinstance(
        response, ChatCompletionResponse
    ):
        return response

    signer = _get_signer()
    # Use exclude_none=False so the signed payload mirrors the JSON body
    # FastAPI returns to the client (its default encoder keeps null fields).
    # Otherwise a verifier that re-canonicalizes the HTTP body would compute
    # a different digest and reject a legitimate signature.
    from llm_sign import project_openai_chat_request, project_openai_chat_response

    request_payload = project_openai_chat_request(
        request.model_dump(mode="json", exclude_none=False)
    )
    response_payload = project_openai_chat_response(
        response.model_dump(mode="json", exclude_none=False)
    )
    envelope: dict[str, Any] = {}
    signer.sign_and_attach(envelope, request_payload, response_payload)
    # ``ChatCompletionResponse`` (via ``OpenAIBaseModel``) sets
    # ``model_config = ConfigDict(extra="allow")``, so the ``llm_sign`` field
    # is a valid dynamic attribute at runtime. mypy cannot see that through
    # pydantic's config, hence the targeted ignore.
    response.llm_sign = envelope["llm_sign"]  # type: ignore[attr-defined]
    return response


class _OpenAILLMSigner:
    def __init__(self) -> None:
        certfile = envs.VLLM_LLM_SIGN_CERTFILE
        keyfile = envs.VLLM_LLM_SIGN_KEYFILE
        if not certfile or not keyfile:
            raise ValueError(
                "VLLM_LLM_SIGN_CERTFILE and VLLM_LLM_SIGN_KEYFILE must be set "
                "when VLLM_LLM_SIGN_ENABLED=1"
            )

        try:
            from llm_sign.server import (
                TLSCertificateCredential,
                attach_signed_artifact_to_openai_response,
                sign_openai_chat_turn,
            )
        except ImportError as exc:
            raise ImportError(
                "llm_sign must be installed when VLLM_LLM_SIGN_ENABLED=1"
            ) from exc

        self._credential = TLSCertificateCredential.from_files(
            ssl_certfile=certfile,
            ssl_keyfile=keyfile,
        )
        self._signer = self._credential.signer()
        self._sign_openai_chat_turn = sign_openai_chat_turn
        self._attach = attach_signed_artifact_to_openai_response

    def sign_and_attach(
        self,
        envelope: dict[str, Any],
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> None:
        artifact = self._sign_openai_chat_turn(
            request=request,
            response=response,
            signer=self._signer,
        )
        self._attach(envelope, artifact=artifact, credential=self._credential)


_signer: _OpenAILLMSigner | None = None


def _get_signer() -> _OpenAILLMSigner:
    global _signer
    if _signer is None:
        _signer = _OpenAILLMSigner()
    return _signer


def clear_cached_signer() -> None:
    global _signer
    _signer = None
