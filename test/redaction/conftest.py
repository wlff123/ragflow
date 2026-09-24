"""Self-contained redaction tests: no NLTK downloads or running RAG services."""

import io
import json

import pytest
from werkzeug.datastructures import FileStorage

from common.enterprise_redaction.engine import get_engine, load_policy


@pytest.fixture(autouse=True)
def policy(tmp_path, monkeypatch):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"business_terms": ["星桥机密项目", "机密13800138000资料"]}), encoding="utf-8")
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "1")
    monkeypatch.setenv("RAGFLOW_REDACTION_POLICY", str(path))
    monkeypatch.setenv("RAGFLOW_REDACTION_HMAC_KEY", "ab" * 32)
    monkeypatch.setenv("RAGFLOW_REDACTION_ISOLATED", "1")
    load_policy.cache_clear()
    get_engine.cache_clear()
    yield path
    load_policy.cache_clear()
    get_engine.cache_clear()


@pytest.fixture
def upload():
    def make(text, name="source.txt"):
        return FileStorage(stream=io.BytesIO(text.encode("utf-8") if isinstance(text, str) else text), filename=name)

    return make
