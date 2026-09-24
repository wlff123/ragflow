import ast
import logging
import os
import time
from functools import wraps
from pathlib import Path
from types import SimpleNamespace

import pytest
from quart import Blueprint, Quart, current_app, request
from werkzeug.exceptions import Unauthorized

from api.utils.redaction_guard import WRITE_ENDPOINTS, allowed, install, validate_dataset_config

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "endpoint,method",
    [
        ("file_api.create_or_upload", "POST"),
        ("file2document_api.convert", "POST"),
        ("chunk_api.add_chunk", "POST"),
        ("chunk_api.update_chunk", "PATCH"),
        ("document_api.update_document", "PATCH"),
        ("document_api.update_metadata", "PATCH"),
        ("document_api.metadata_batch_update", "POST"),
        ("document_api.update_metadata_config", "PUT"),
        ("dataset_api.update_wiki_page", "PUT"),
        ("document_api.upload_info", "POST"),
        ("connector_api.sync", "POST"),
        ("connector_api.oauth_callback", "GET"),
        ("agent_api.run", "POST"),
        ("backward_compat.upload_document", "POST"),
        ("future_api.new_writer", "POST"),
        (None, "POST"),
    ],
)
def test_bypass_endpoints_denied(endpoint, method):
    assert not allowed(endpoint, method, {})


def test_allowed_endpoint_names_exist():
    root = ROOT / "api/apps/restful_apis"
    for endpoint in WRITE_ENDPOINTS:
        module, function = endpoint.split(".")
        tree = ast.parse((root / f"{module}.py").read_text(encoding="utf-8"))
        assert any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == function and n.decorator_list for n in tree.body), endpoint


@pytest.mark.parametrize("kind", ["web", "empty", "unknown"])
def test_upload_kind_denied(kind):
    assert not allowed("document_api.upload_document", "POST", {"type": kind})


async def test_quart_guard_enforced_and_disabled_mode_unchanged(monkeypatch):
    app = Quart(__name__)
    install(app)

    async def ok():
        return {"ok": True}

    app.add_url_rule("/upload", endpoint="document_api.upload_document", view_func=ok, methods=["POST"])
    app.add_url_rule("/unsafe", endpoint="chunk_api.add_chunk", view_func=ok, methods=["POST"])
    client = app.test_client()
    assert (await client.post("/upload")).status_code == 200
    assert (await client.post("/upload?type=web")).status_code == 403
    assert (await client.post("/unsafe")).status_code == 403
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "0")
    assert (await client.post("/unsafe")).status_code == 200


@pytest.mark.parametrize("function,method,url", [("create", "POST", "/datasets"), ("update", "PUT", "/datasets/kb")])
async def test_dataset_auth_precedes_config_check_and_writes(function, method, url, monkeypatch):
    from common.enterprise_redaction import engine

    app = Quart(__name__)
    install(app)
    manager = Blueprint("dataset_api", __name__)
    writes, checks = [], []
    original = engine.validate_text_fields

    def check(value):
        checks.append(True)
        return original(value)

    monkeypatch.setattr(engine, "validate_text_fields", check)

    async def save(*args):
        writes.append(True)
        return True, {"ok": True}

    async def parse(*args, **kwargs):
        return await request.get_json(), None

    def tenant(func):
        @wraps(func)
        async def wrapper(**kwargs):
            return await func(tenant_id="tenant", **kwargs)

        return wrapper

    # Execute the real auth decorator and route, stubbing auth/DB dependencies.
    namespace = dict(
        wraps=wraps,
        os=os,
        time=time,
        logging=logging,
        request=request,
        current_app=current_app,
        _load_user=lambda _: request.headers.get("Authorization"),
        _normalize_auth_types=lambda _: {"jwt"},
        AUTH_BETA="beta",
        QuartAuthUnauthorized=Unauthorized,
        manager=manager,
        add_tenant_id_to_kwargs=tenant,
        validate_dataset_config=validate_dataset_config,
        validate_and_parse_json_request=parse,
        CreateDatasetReq=None,
        UpdateDatasetReq=None,
        dataset_api_service=SimpleNamespace(create_dataset=save, update_dataset=save),
        get_result=lambda **kw: kw,
    )
    for path, name in [("api/apps/__init__.py", "login_required"), ("api/apps/restful_apis/dataset_api.py", function)]:
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        node = next(n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
        exec("from __future__ import annotations\n" + ast.unparse(node), namespace)
    app.register_blueprint(manager)
    client = app.test_client()
    unsafe = {"parser_config": {"metadata": {"properties": {"phone": {"enum": ["13800138000"]}}}}}
    assert (await client.open(url, method=method, json=unsafe)).status_code == 401
    assert checks == writes == []
    headers = {"Authorization": "test-user"}
    response = await client.open(url, method=method, json=unsafe, headers=headers)
    assert response.status_code == 400
    assert (await response.get_json())["message"] == "REDACTION_CONFIG_CONTAINS_SENSITIVE_TEXT"
    assert checks == [True] and writes == []
    assert (await client.open(url, method=method, json={"parser_config": {"chunk_token_num": 128}}, headers=headers)).status_code == 200
    assert writes == [True]
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "0")
    assert (await client.open(url, method=method, json=unsafe, headers=headers)).status_code == 200
    assert checks == [True, True] and writes == [True, True]
