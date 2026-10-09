"""OpenAI-compatible JSON completions, configured only via REVA_* environment variables."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "http://localhost:19060/v1"
DEFAULT_MODEL = "meta-models/Muse-Glimmer-30B"
MAX_TOKENS = 8192
PROBE_TIMEOUT = 5.0   # a hosted endpoint is a TLS handshake away, not a loopback socket
_REACHED: set[str] = set()


def _base_url() -> str:
    return os.environ.get("REVA_BASE_URL", DEFAULT_BASE_URL)


def _api_key() -> str:
    return os.environ.get("REVA_API_KEY", "none")


def available() -> bool:
    """True if the configured endpoint answers; callers degrade to offline behaviour otherwise.
    Only a success is remembered: one dropped probe must not silence the LLM for the rest of the run.
    The key is sent on the probe and an HTTP status is proof of life: a hosted endpoint answers
    /models with 401 without it, and a 4xx there must not be read as "no LLM" and silence the screen."""
    url = _base_url()
    if url in _REACHED:
        return True
    req = urllib.request.Request(url.rstrip("/") + "/models",
                                 headers={"Authorization": f"Bearer {_api_key()}"})
    try:
        urllib.request.urlopen(req, timeout=PROBE_TIMEOUT).close()
    except urllib.error.HTTPError:
        pass
    except OSError:
        return False
    _REACHED.add(url)
    return True


def _last_json_object(text: str) -> dict | None:
    decoder, found, i = json.JSONDecoder(), None, text.find("{")
    while i != -1:
        try:
            obj, end = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            i = text.find("{", i + 1)
            continue
        found = obj if isinstance(obj, dict) else found
        i = text.find("{", end)
    return found


def complete_json(system: str, user: str, schema_hint: str = "") -> dict:
    """One call asking for a JSON object; retries once if none can be parsed. Raises RuntimeError on failure."""
    from openai import OpenAI

    client = OpenAI(base_url=_base_url(), api_key=_api_key())
    hint = f" matching: {schema_hint}" if schema_hint else ""
    messages = [
        {"role": "system", "content": f"{system}\nRespond with a single JSON object{hint} and nothing else."},
        {"role": "user", "content": user},
    ]
    for _ in range(2):
        try:
            msg = client.chat.completions.create(
                model=os.environ.get("REVA_MODEL", DEFAULT_MODEL), messages=messages, temperature=0, max_tokens=MAX_TOKENS
            ).choices[0].message
        except Exception as e:
            raise RuntimeError(f"LLM request failed: {e}") from e
        text = msg.content or getattr(msg, "reasoning", None) or getattr(msg, "reasoning_content", None) or ""
        obj = _last_json_object(text)
        if obj is not None:
            return obj
        messages += [{"role": "assistant", "content": text[-2000:]}, {"role": "user", "content": "Reply with only the JSON object."}]
    raise RuntimeError("LLM returned no valid JSON twice")
