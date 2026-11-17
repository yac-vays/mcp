import time

import pytest

from app.lib import envelope
from app.model.err import ConfigError, EnvelopeError


def test_roundtrip_and_type_binding():
    sealed = envelope.seal("access", {"sub": "alice", "nested": {"a": [1, 2]}}, ttl=60)
    data = envelope.open_("access", sealed)
    assert data["sub"] == "alice" and data["nested"] == {"a": [1, 2]}
    with pytest.raises(EnvelopeError):
        envelope.open_("refresh", sealed)


def test_expired():
    sealed = envelope.seal("code", {}, exp=int(time.time()) - 1)
    with pytest.raises(EnvelopeError, match="expired"):
        envelope.open_("code", sealed)


def test_tampered_and_garbage():
    sealed = envelope.seal("code", {"x": 1})
    head, rest = sealed[:-6], sealed[-6:]
    tampered = head + ("A" if rest[0] != "A" else "B") + rest[1:]
    for value in (tampered, "garbage", "a.b.c.d.e", ""):
        with pytest.raises(EnvelopeError):
            envelope.open_("code", value)


def test_rotation(monkeypatch):
    sealed_with_k1 = envelope.seal("client", {"n": 1})
    old_keys = list(envelope.consts.ENV.keys)
    new_key = envelope.generate_key()
    monkeypatch.setattr(envelope.consts.ENV, "keys", [new_key, *old_keys])
    envelope._keys.cache_clear()  # pylint: disable=protected-access
    try:
        assert envelope.open_("client", sealed_with_k1)["n"] == 1
        sealed_with_new = envelope.seal("client", {"n": 2})
        monkeypatch.setattr(envelope.consts.ENV, "keys", old_keys)
        envelope._keys.cache_clear()  # pylint: disable=protected-access
        with pytest.raises(EnvelopeError):
            envelope.open_("client", sealed_with_new)
    finally:
        envelope._keys.cache_clear()  # pylint: disable=protected-access


def test_issuer_binding(monkeypatch):
    sealed = envelope.seal("access", {})
    monkeypatch.setattr(envelope.consts.ENV, "public_url", "https://other.test")
    with pytest.raises(EnvelopeError, match="another server"):
        envelope.open_("access", sealed)


def test_bad_key_config(monkeypatch):
    for keys in ([], ["nokid"], ["k:short"]):
        monkeypatch.setattr(envelope.consts.ENV, "keys", keys)
        envelope._keys.cache_clear()  # pylint: disable=protected-access
        with pytest.raises(ConfigError):
            envelope.seal("x", {})
    envelope._keys.cache_clear()  # pylint: disable=protected-access
