"""Ollama health-check behavior without a running daemon."""

from __future__ import annotations

from forensicagent.llm.ollama_client import OllamaClient
from forensicagent.llm.ollama_client import _response_content


class _FakeClient:
    def __init__(self, names):
        self._names = names

    def list(self):
        return {"models": [{"name": name} for name in self._names]}


def test_health_check_requires_exact_requested_model_tag(monkeypatch):
    client = OllamaClient(model="qwen2.5:14b")
    monkeypatch.setattr(
        client,
        "_client",
        lambda **kwargs: _FakeClient(["qwen2.5:3b", "llama3.1:8b"]),
    )

    ok, detail = client.is_available()

    assert ok is False
    assert "qwen2.5:14b" in detail


def test_health_check_accepts_exact_requested_model_tag(monkeypatch):
    client = OllamaClient(model="qwen2.5:14b")
    monkeypatch.setattr(
        client,
        "_client",
        lambda **kwargs: _FakeClient(["qwen2.5:14b"]),
    )

    ok, _ = client.is_available()

    assert ok is True


def test_response_content_supports_dict_and_modern_object_shape():
    class Message:
        content = "modern"

    class Response:
        message = Message()

    assert _response_content({"message": {"content": "legacy"}}) == "legacy"
    assert _response_content(Response()) == "modern"
