"""Execute production upload/queue bodies and adapter against real SQLite.

AST loading skips RAGFlow's unrelated startup imports (OCR/GPU/model downloads).
The functions and model field definitions are read unchanged from the checkout.
External storage is an inspectable fake; this is not a full-service E2E test.
"""

import ast
import copy
import hashlib
import importlib.util
import json
import logging
import os
import re
import sys
import types
from pathlib import Path, PurePath
from types import SimpleNamespace
from uuid import uuid4

import peewee
import pytest
from playhouse.sqlite_ext import JSONField

from common.enterprise_redaction import RedactionError

ROOT = Path(__file__).resolve().parents[2]


def source_node(path, name, parent=None):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    nodes = tree.body if parent is None else next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == parent).body
    return next(n for n in nodes if getattr(n, "name", None) == name)


def load_function(path, name, namespace, parent=None):
    node = source_node(path, name, parent)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / path), "exec"), namespace)
    return namespace[name]


class Storage:
    def __init__(self):
        self.objects = {}
        self.writes = []
        self.drop_writes = False

    def put(self, bucket, name, blob, tenant_id=None):
        self.writes.append((bucket, name, blob))
        if not self.drop_writes:
            self.objects[bucket, name] = blob

    def get(self, bucket, name, tenant_id=None):
        return self.objects.get((bucket, name))

    def rm(self, bucket, name, tenant_id=None):
        self.objects.pop((bucket, name), None)

    def obj_exist(self, bucket, name):
        return (bucket, name) in self.objects


@pytest.fixture
def rag(tmp_path, monkeypatch):
    db = peewee.SqliteDatabase(tmp_path / "database.sqlite")

    class Base(peewee.Model):
        class Meta:
            database = db

    namespace = {**vars(peewee), "os": os, "DataBaseModel": Base, "JSONField": JSONField, "EmptyStringCharField": peewee.CharField, "ParserType": SimpleNamespace(NAIVE=SimpleNamespace(value="naive"))}
    models = types.ModuleType("api.db.db_models")
    models.DB = db
    names = ["Document", "File", "File2Document", "Knowledgebase", "RedactionRecord"]
    for name in names:
        node = source_node("api/db/db_models.py", name)
        exec(compile(ast.Module(body=[node], type_ignores=[]), "db_models.py", "exec"), namespace)
        setattr(models, name, namespace[name])
    db.create_tables([getattr(models, name) for name in names])
    kb = models.Knowledgebase.create(id="kb", tenant_id="tenant", name="测试库", created_by="user", embd_id="test", parser_id="naive", pipeline_id=None)
    storage = Storage()
    settings = types.ModuleType("common.settings")
    settings.STORAGE_IMPL = storage
    monkeypatch.setitem(sys.modules, "common.settings", settings)
    import common

    monkeypatch.setattr(common, "settings", settings, raising=False)
    monkeypatch.setitem(sys.modules, "api.db.db_models", models)
    name = "api.db.services.redaction_service"
    spec = importlib.util.spec_from_file_location(name, ROOT / "api/db/services/redaction_service.py")
    service = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, service)
    spec.loader.exec_module(service)

    def get_by_id(doc_id):
        doc = models.Document.get_or_none(models.Document.id == doc_id)
        return doc is not None, doc

    document_service = SimpleNamespace(model=models.Document, get_by_id=get_by_id, check_doc_health=lambda *a: None, query=lambda **kw: list(models.Document.select().filter(**kw)))
    file_service = SimpleNamespace(
        model=models.File,
        get_root_folder=lambda u: {"id": "root"},
        init_knowledgebase_docs=lambda *a: None,
        get_kb_folder=lambda u: {"id": "kb-root"},
        new_a_file_from_kb=lambda *a: {"id": "folder"},
        get_parser=lambda *a: "naive",
    )
    filetype = SimpleNamespace(**{name: SimpleNamespace(value=name.lower()) for name in ("OTHER", "PDF", "DOC", "AURAL", "VISUAL")})
    ns = dict(
        DB=db,
        Knowledgebase=models.Knowledgebase,
        File2Document=models.File2Document,
        RedactionRecord=models.RedactionRecord,
        FileSource=SimpleNamespace(KNOWLEDGEBASE="knowledgebase"),
        DocumentService=document_service,
        FileService=file_service,
        settings=settings,
        sanitize_path=lambda p: p,
        FileType=filetype,
        FILE_NAME_LEN_LIMIT=255,
        re=re,
        os=os,
        PurePath=PurePath,
        thumbnail_img=lambda *a: None,
        Path=Path,
        get_uuid=lambda: uuid4().hex,
        xxhash=SimpleNamespace(xxh128=lambda blob: hashlib.md5(blob)),
        logger=logging.getLogger("redaction-test"),
    )
    for path, name in [
        ("api/utils/file_utils.py", "_normalize_filename_for_type"),
        ("api/utils/file_utils.py", "filename_type"),
        ("api/db/services/__init__.py", "_split_name_counter"),
        ("api/db/services/__init__.py", "duplicate_name"),
    ]:
        load_function(path, name, ns)
    insert = load_function("api/db/services/document_service.py", "_insert", ns, "DocumentService")
    document_service._insert = lambda doc: insert(document_service, doc)
    link = load_function("api/db/services/file_service.py", "_add_file_from_kb", ns, "FileService")
    file_service._add_file_from_kb = lambda *args: link(file_service, *args)
    # SQLite has no SELECT FOR UPDATE; the transaction rollback is exercised
    # here, while row-lock behavior belongs to the MySQL integration test.
    monkeypatch.setattr(peewee.ModelSelect, "for_update", lambda self, *a, **kw: self)
    delete = load_function("api/db/services/document_service.py", "delete_document_and_update_kb_counts", ns, "DocumentService")
    document_service.delete_document_and_update_kb_counts = lambda doc_id: delete(document_service, doc_id)
    upload_method = load_function("api/db/services/file_service.py", "upload_document", ns, "FileService")
    yield SimpleNamespace(db=db, models=models, kb=kb, storage=storage, service=service, ns=ns, upload=lambda files, **kw: upload_method(file_service, kb, files, "user", **kw))
    db.close()


def test_upload_storage_sql_and_receipt_contain_only_safe_values(rag, upload):
    errors, files = rag.upload([upload("电话13800138000；星桥机密项目", "13800138000.txt")])
    assert not errors
    doc, blob = files[0]
    assert blob.decode() == "电话[已剔除]；[已剔除]"
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 1
    assert rag.models.Document.select().count() == rag.models.File.select().count() == rag.models.RedactionRecord.select().count() == 1
    for model in [rag.models.Document, rag.models.File, rag.models.RedactionRecord]:
        assert "13800138000" not in repr(list(model.select().dicts()))
    assert all(b"13800138000" not in written[2] and "13800138000" not in written[1] for written in rag.storage.writes)
    rag.service.verify_document(doc["id"], "tenant", "kb", "kb", doc["location"])
    rag.service.validate_startup()


def test_preprocessing_batch_failure_makes_no_writes(rag, upload):
    with pytest.raises(RedactionError, match="FORMAT"):
        rag.upload([upload("13800138000"), upload("unsupported", "raw.pdf")])
    assert rag.storage.writes == []
    assert rag.models.Document.select().count() == 0


def test_dense_matches_reject_entire_batch_without_writes(rag, upload):
    with pytest.raises(RedactionError, match="REDACTION_MATCH_LIMIT"):
        rag.upload([upload("public report"), upload("13800138000 " * 15000)])
    assert rag.storage.writes == []
    assert rag.models.Document.select().count() == rag.models.RedactionRecord.select().count() == 0


def test_silent_object_store_failure_does_not_publish(rag, upload):
    rag.storage.drop_writes = True
    errors, files = rag.upload([upload("13800138000")])
    assert errors == ["REDACTION_PUBLISH_FAILED"]
    assert not files
    assert rag.models.Document.select().count() == rag.models.RedactionRecord.select().count() == 0


def test_database_failure_rolls_back_all_rows_and_safe_object(rag, upload, monkeypatch):
    def fail(**kwargs):
        raise RuntimeError("simulated database failure")

    monkeypatch.setattr(rag.models.File2Document, "create", fail)
    errors, files = rag.upload([upload("13800138000")])
    assert errors == ["REDACTION_PUBLISH_FAILED"] and not files
    for model in [rag.models.Document, rag.models.File, rag.models.File2Document, rag.models.RedactionRecord]:
        assert model.select().count() == 0
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 0
    assert not rag.storage.objects


def test_worker_and_queue_reject_tampered_document(rag, upload):
    _, files = rag.upload([upload("13800138000")])
    doc = files[0][0]
    task = {"doc_id": doc["id"], "tenant_id": "tenant", "kb_id": "kb"}
    rag.service.verify_task(task)
    rag.storage.objects["kb", doc["location"]] = b"13800138000"
    with pytest.raises(RedactionError, match="RECEIPT_INVALID"):
        rag.service.verify_task(task)
    queue = load_function("api/db/services/task_service.py", "queue_tasks", {})
    with pytest.raises(RedactionError, match="RECEIPT_INVALID"):
        queue(doc, "kb", doc["location"], 0)


def test_missing_receipt_startup_and_dataflow_fail_closed(rag, upload):
    _, files = rag.upload([upload("13800138000")])
    rag.models.RedactionRecord.delete().execute()
    with pytest.raises(RedactionError, match="UNVERIFIED"):
        rag.service.validate_startup()
    queue = load_function("api/db/services/task_service.py", "queue_dataflow", {"CANVAS_DEBUG_DOC_ID": "debug"})
    with pytest.raises(RedactionError, match="UNVERIFIED"):
        queue("tenant", "flow", "task", files[0][0]["id"])
    with pytest.raises(RedactionError, match="OVERRIDE_UNSUPPORTED"):
        queue("tenant", "flow", "task", file={"raw": "13800138000"})


@pytest.mark.parametrize("option", [{"src": "s3"}, {"parent_path": "13800138000"}, {"parser_config_override": {"table_column_roles": ["secret"]}}])
def test_source_options_cannot_bypass(rag, upload, option):
    with pytest.raises(RedactionError, match="UPLOAD_OPTIONS"):
        rag.upload([upload("raw")], **option)
    assert not rag.storage.writes


def test_legacy_mode_keeps_original_filename_and_bytes(rag, upload, monkeypatch):
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "0")
    errors, files = rag.upload([upload("13800138000", "original.txt")])
    assert not errors
    assert files[0][0]["name"] == "original.txt"
    assert files[0][1] == b"13800138000"
    assert rag.models.RedactionRecord.select().count() == 0


def test_foreign_tenant_and_file_link_cannot_replay(rag, upload):
    _, files = rag.upload([upload("13800138000")])
    doc = files[0][0]
    with pytest.raises(RedactionError, match="SCOPE_MISMATCH"):
        rag.service.verify_document(doc["id"], "another-tenant")
    rag.models.File.update(source_type="").execute()
    with pytest.raises(RedactionError, match="FILE_LINK_INVALID"):
        rag.service.verify_document(doc["id"])


@pytest.mark.parametrize("dangling_link", [False, True])
def test_startup_rejects_files_without_an_existing_document(rag, upload, dangling_link):
    rag.upload([upload("public report")])
    rag.models.File.create(id="orphan", parent_id="root", tenant_id="tenant", created_by="user", name="orphan.txt", type="doc", size=1, location="orphan.txt")
    if dangling_link:
        rag.models.File2Document.create(id="link", file_id="orphan", document_id="missing")
    with pytest.raises(RedactionError, match="EXISTING_FILE_UNVERIFIED"):
        rag.service.validate_startup()


def test_source_worker_verifies_before_any_model_call():
    node = source_node("rag/svr/task_executor.py", "handle_task")
    dispatch = next(n for n in node.body if isinstance(n, ast.Try))
    calls = [n for n in ast.walk(ast.Module(body=dispatch.body[:2], type_ignores=[])) if isinstance(n, ast.Name)]
    assert any(n.id == "verify_task" for n in calls)


def test_engine_error_does_not_leak_exception(rag, upload, monkeypatch):
    import common.enterprise_redaction.engine as engine

    def fail():
        raise RuntimeError("raw-password-should-not-be-returned")

    monkeypatch.setattr(engine, "get_engine", fail)
    with pytest.raises(RedactionError) as error:
        rag.upload([upload("13800138000")])
    assert str(error.value) == "REDACTION_CONFIG_INVALID"
    assert not rag.storage.writes


async def test_default_worker_rejects_tamper_before_refactored_executor(rag, upload, monkeypatch):
    _, files = rag.upload([upload("13800138000")])
    doc = files[0][0]
    task = {"id": "task", "doc_id": doc["id"], "tenant_id": "tenant", "kb_id": "kb", "task_type": ""}
    events = []

    async def collect():
        return SimpleNamespace(ack=lambda: events.append("ack")), task

    async def thread_pool(func, *args, **kwargs):
        return func(*args, **kwargs)

    async def execute(*args):
        events.append("execute")

    monkeypatch.setenv("TE_RUN_MODE", "0")
    namespace = dict(
        DONE_TASKS=0,
        FAILED_TASKS=0,
        CURRENT_TASKS={},
        collect=collect,
        thread_pool_exec=thread_pool,
        TASK_TYPE_TO_PIPELINE_TASK_TYPE={},
        PipelineTaskType=SimpleNamespace(PARSE="parse"),
        set_llm_request_context=lambda **kw: None,
        normalize_llm_user_id=lambda value: value,
        reset_llm_request_context=lambda token: None,
        logging=logging,
        json=json,
        copy=copy,
        os=os,
        set_recording_context=lambda value: None,
        NullRecordingContext=lambda: None,
        get_recording_context=lambda: SimpleNamespace(save_func_return_value=lambda *a: None),
        TaskManager=SimpleNamespace(run_refactored_task=execute),
        chat_limiter=None,
        minio_limiter=None,
        chunk_limiter=None,
        embed_limiter=None,
        kg_limiter=None,
        has_canceled=lambda *a: False,
        TaskCanceledException=type("Canceled", (Exception,), {}),
        exceptiongroup=SimpleNamespace(ExceptionGroup=ExceptionGroup),
        set_progress=lambda *a, **kw: events.append(kw.get("msg")),
        _KB_FANOUT_TASK_TYPES=set(),
        PipelineOperationLogService=SimpleNamespace(record_pipeline_operation=lambda **kw: None),
    )
    namespace["_redact_task_user"] = load_function("rag/svr/task_executor.py", "_redact_task_user", {})
    handle = load_function("rag/svr/task_executor.py", "handle_task", namespace)
    assert await handle()
    assert events == ["execute", "ack"]
    events.clear()
    rag.storage.objects["kb", doc["location"]] = b"13800138000"
    assert await handle()
    assert "execute" not in events and "ack" in events
    assert namespace["FAILED_TASKS"] == 1
    assert any("RECEIPT_INVALID" in (event or "") for event in events)


def test_sensitive_kb_config_is_rejected_before_storage(rag, upload):
    rag.kb.parser_config = {"metadata": {"properties": {"contact": {"enum": ["13800138000"]}}}}
    with pytest.raises(RedactionError, match="CONFIG_CONTAINS_SENSITIVE_TEXT"):
        rag.upload([upload("Public report")])
    assert rag.storage.writes == []
    assert rag.models.Document.select().count() == 0


@pytest.mark.parametrize("model", ["Document", "Knowledgebase"])
def test_changed_config_is_rejected_before_worker(rag, upload, model):
    _, files = rag.upload([upload("Public report")])
    getattr(rag.models, model).update(parser_config={"metadata": {"contact": "13800138000"}}).execute()
    with pytest.raises(RedactionError, match="CONFIG_CONTAINS_SENSITIVE_TEXT"):
        rag.service.verify_task({"doc_id": files[0][0]["id"]})


def test_partial_rule_results_are_never_published(rag, upload, monkeypatch):
    from common.enterprise_redaction.engine import get_engine

    rule = next(r for r in get_engine().analyzer.registry.recognizers if r.name == "EMAIL_ADDRESS")
    original = rule.pattern

    class InterruptedPattern:
        def finditer(self, text, **kwargs):
            yield from original.finditer(text, **kwargs)
            if "TRIGGER" in text:
                raise TimeoutError("simulated after a partial match")

    monkeypatch.setattr(rule, "pattern", InterruptedPattern())
    with pytest.raises(RedactionError, match="RULE_TIMEOUT"):
        rag.upload([upload("public report"), upload("private@example.com TRIGGER")])
    assert rag.storage.writes == []
    assert rag.models.Document.select().count() == rag.models.RedactionRecord.select().count() == 0


@pytest.mark.parametrize("protected", ["0", "1"])
def test_shared_publication_is_atomic(rag, upload, monkeypatch, protected):
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", protected)

    def fail(**kwargs):
        raise RuntimeError("link creation failed")

    monkeypatch.setattr(rag.models.File2Document, "create", fail)
    errors, files = rag.upload([upload("public report")])
    assert errors and not files
    for model in (rag.models.Document, rag.models.File, rag.models.File2Document, rag.models.RedactionRecord):
        assert model.select().count() == 0
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 0


@pytest.mark.parametrize("enabled_at_delete", ["0", "1"])
def test_document_delete_removes_only_its_receipt_and_is_idempotent(rag, upload, monkeypatch, enabled_at_delete):
    _, files = rag.upload([upload("first"), upload("second")])
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", enabled_at_delete)
    delete = rag.ns["DocumentService"].delete_document_and_update_kb_counts
    first, second = (item[0]["id"] for item in files)
    assert delete(first)
    assert not delete(first)
    assert not rag.models.RedactionRecord.get_or_none(rag.models.RedactionRecord.id == first)
    assert rag.models.RedactionRecord.get_by_id(second)
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 1


def test_receipt_insert_failure_rolls_back_publication(rag, upload, monkeypatch):
    def fail(**kwargs):
        raise RuntimeError("receipt creation failed")

    monkeypatch.setattr(rag.models.RedactionRecord, "create", fail)
    errors, files = rag.upload([upload("public report")])
    assert errors == ["REDACTION_PUBLISH_FAILED"] and not files
    for model in (rag.models.Document, rag.models.File, rag.models.File2Document, rag.models.RedactionRecord):
        assert model.select().count() == 0
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 0
    assert not rag.storage.objects


def test_receipt_delete_failure_rolls_back_document_and_count(rag, upload, monkeypatch):
    _, files = rag.upload([upload("public report")])
    doc_id = files[0][0]["id"]

    def fail():
        raise RuntimeError("receipt delete failed")

    monkeypatch.setattr(rag.models.RedactionRecord, "delete", fail)
    with pytest.raises(RuntimeError, match="receipt delete failed"):
        rag.ns["DocumentService"].delete_document_and_update_kb_counts(doc_id)
    assert rag.models.Document.get_by_id(doc_id)
    assert rag.models.RedactionRecord.get_by_id(doc_id)
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 1


def test_zip_plain_mode_keeps_all_files_and_renames_collisions(rag, upload, zip_upload, monkeypatch):
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "0")
    errors, files = rag.upload([zip_upload([("one/report.txt", "first"), ("two/report.txt", "second")]), upload("plain", "loose.txt")])
    assert not errors
    assert [doc["name"] for doc, _ in files] == ["report.txt", "report(1).txt", "loose.txt"]
    assert [blob for _, blob in files] == [b"first", b"second", b"plain"]
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 3
    assert rag.models.RedactionRecord.select().count() == 0
    assert len(rag.storage.objects) == 3


def test_zip_every_member_redacted_and_receipt_bound(rag, zip_upload):
    errors, files = rag.upload(
        [
            zip_upload(
                [
                    ("13800138000/raw.txt", "电话13800138000"),
                    ("private@example.com/summary.md", "# 项目\n星桥机密项目"),
                    ("table.csv", "邮箱,手机号\nprivate@example.com,13800138000"),
                ],
                "private@example.com.zip",
            )
        ]
    )
    assert not errors and len(files) == 3
    for doc, blob in files:
        assert "[已剔除]" in blob.decode()
        assert doc["name"].startswith("文档-")
        rag.service.verify_document(doc["id"], "tenant", "kb", "kb", doc["location"])
    assert rag.models.RedactionRecord.select().count() == 3
    published = repr(rag.storage.writes) + repr([list(model.select().dicts()) for model in (rag.models.Document, rag.models.File, rag.models.RedactionRecord)])
    assert all(secret not in published for secret in ("13800138000", "private@example.com", "星桥机密项目"))
    assert not any(name.endswith(".zip") for _, name in rag.storage.objects)


@pytest.mark.parametrize(
    "entries,error",
    [
        ([("ok.txt", "valid"), ("bad.pdf", "raw")], "REDACTION_FILE_FORMAT_UNSUPPORTED"),
        ([("ok.txt", "valid"), ("bad.txt", b"\xff")], "REDACTION_UTF8_REQUIRED"),
        ([("ok.txt", "valid"), ("bad.exe", "raw")], "ZIP_MEMBER_FORMAT_UNSUPPORTED"),
        ([("ok.txt", "valid"), ("../bad.txt", "raw")], "ZIP_UNSAFE_PATH"),
        ([(f"{i}.txt", "valid") for i in range(6)], "ZIP_FILE_COUNT_LIMIT"),
    ],
)
def test_zip_batch_failure_publishes_nothing(rag, upload, zip_upload, entries, error):
    with pytest.raises(ValueError, match=error):
        rag.upload([upload("plain"), zip_upload(entries)])
    assert rag.storage.writes == []
    for model in (rag.models.Document, rag.models.File, rag.models.RedactionRecord):
        assert model.select().count() == 0


def test_zip_member_size_uses_redaction_limit(rag, zip_upload):
    import zipfile

    with pytest.raises(ValueError, match="ZIP_MEMBER_SIZE_LIMIT"):
        rag.upload([zip_upload([("big.txt", b"x" * (2 * 1024 * 1024 + 1))], compression=zipfile.ZIP_STORED)])
    assert rag.storage.writes == []


def test_zip_publication_failure_returns_successful_members_only(rag, zip_upload, monkeypatch):
    original = rag.storage.put

    def fail_second(*args, **kwargs):
        if rag.storage.writes:
            raise OSError("simulated storage outage")
        return original(*args, **kwargs)

    monkeypatch.setattr(rag.storage, "put", fail_second)
    errors, files = rag.upload([zip_upload([("a.txt", "13800138000"), ("b.txt", "private@example.com")])])
    assert errors == ["REDACTION_PUBLISH_FAILED"] and len(files) == 1
    assert rag.models.Document.select().count() == rag.models.RedactionRecord.select().count() == 1
    assert rag.models.Knowledgebase.get_by_id("kb").doc_num == 1
    assert len(rag.storage.objects) == 1


@pytest.mark.parametrize("protected", ["0", "1"])
async def test_zip_real_http_sqlite_and_disk(rag, zip_upload, tmp_path, monkeypatch, protected):
    """Real loopback HTTP and disk I/O; production route/service/Presidio bodies.

    SQLite replaces MySQL; filesystem objects replace MinIO. Authentication
    lookup and parser dependencies are fixtures, not a complete RAGFlow server.
    """
    import asyncio
    import socket
    import time
    from functools import wraps

    import httpx
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    from quart import Quart, current_app, jsonify, request
    from werkzeug.exceptions import Unauthorized

    from api.utils.redaction_guard import install
    from common.constants import RetCode, TaskStatus
    from common.zip_upload import ZipUploadError

    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", protected)
    object_dir = tmp_path / "objects"
    object_dir.mkdir()

    def object_path(bucket, name):
        return object_dir / bucket / name

    def put(bucket, name, blob, tenant_id=None):
        target = object_path(bucket, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)

    rag.ns["settings"].STORAGE_IMPL = SimpleNamespace(
        put=put,
        get=lambda bucket, name, *a: object_path(bucket, name).read_bytes(),
        rm=lambda bucket, name, *a: object_path(bucket, name).unlink(missing_ok=True),
        obj_exist=lambda bucket, name: object_path(bucket, name).exists(),
    )

    async def thread_pool(func, *args, **kwargs):
        def run():
            with rag.db.connection_context():
                return func(*args, **kwargs)

        return await asyncio.to_thread(run)

    ns = dict(
        request=request,
        current_app=current_app,
        logging=logging,
        json=json,
        RetCode=RetCode,
        TaskStatus=TaskStatus,
        ZipUploadError=ZipUploadError,
        FILE_NAME_LEN_LIMIT=255,
        _safe_jsonify=jsonify,
        thread_pool_exec=thread_pool,
        FileService=SimpleNamespace(upload_document=lambda kb, files, user, **kw: rag.upload(files, **kw)),
        KnowledgebaseService=SimpleNamespace(get_by_id=lambda id: (id == "kb", rag.kb)),
        check_kb_team_permission=lambda *a: request.headers.get("X-Test-Deny") != "1",
        wraps=wraps,
        os=os,
        time=time,
        AUTH_BETA="beta",
        QuartAuthUnauthorized=Unauthorized,
        _normalize_auth_types=lambda _: {"jwt"},
        _load_user=lambda _: request.headers.get("Authorization") == "Bearer zip-local-test",
    )
    for name in ("strip_graphrag_raptor_config", "get_result", "get_error_data_result", "construct_json_result"):
        load_function("api/utils/api_utils.py", name, ns)
    for name in ("_process_key_mappings", "_process_run_mapping", "map_doc_keys_with_run_status"):
        load_function("api/apps/services/document_api_service.py", name, ns)
    for name in ("_upload_local_documents", "upload_document"):
        load_function("api/apps/restful_apis/document_api.py", name, ns)
    node = source_node("api/apps/__init__.py", "login_required")
    exec("from __future__ import annotations\n" + ast.unparse(node), ns)

    app = Quart(__name__)
    install(app)

    @ns["login_required"]
    async def endpoint(dataset_id):
        return await ns["upload_document"](dataset_id, "tenant")

    app.add_url_rule("/api/v1/datasets/<dataset_id>/documents", endpoint="document_api.upload_document", view_func=endpoint, methods=["POST"])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = Config()
    config.bind = [f"127.0.0.1:{port}"]
    config.accesslog = config.errorlog = None
    shutdown = asyncio.Event()
    server = asyncio.create_task(serve(app, config, shutdown_trigger=shutdown.wait))
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False, timeout=10) as client:
            for _ in range(100):
                if server.done():
                    await server
                try:
                    await client.get("/")
                    break
                except httpx.ConnectError:
                    await asyncio.sleep(0.02)
            url = "/api/v1/datasets/kb/documents"
            body = zip_upload([("one/report.txt", "电话13800138000"), ("two/report.txt", "邮箱private@example.com"), ("三/摘要.md", "# 星桥机密项目")]).read()
            headers = {"Authorization": "Bearer zip-local-test"}
            assert (await client.post(url, files={"file": ("batch.zip", body)})).status_code == 401
            denied = await client.post(url, headers={**headers, "X-Test-Deny": "1"}, files={"file": ("batch.zip", body)})
            assert denied.json()["code"] == RetCode.AUTHENTICATION_ERROR
            assert not list(object_dir.rglob("*.txt"))
            response = await client.post(url, headers=headers, files={"file": ("batch.zip", body)})
            result = response.json()
            assert response.status_code == 200 and result["code"] == 0, result
            docs = result["data"]
            assert len(docs) == 3 and len({doc["id"] for doc in docs}) == 3
            assert all(doc["dataset_id"] == "kb" and doc["run"] == "UNSTART" for doc in docs)
            assert rag.models.Document.select().count() == rag.models.Knowledgebase.get_by_id("kb").doc_num == 3
            objects = [p for p in object_dir.rglob("*") if p.is_file()]
            assert len(objects) == 3 and not any(p.suffix == ".zip" for p in objects)
            text = "\n".join(p.read_text(encoding="utf-8") for p in objects)
            if protected == "1":
                assert "13800138000" not in text and "private@example.com" not in text and "星桥机密项目" not in text
                assert text.count("[已剔除]") == 3
                for doc in list(rag.models.Document.select()):
                    rag.service.verify_document(doc.id, "tenant", "kb", "kb", doc.location)
                assert rag.models.RedactionRecord.select().count() == 3
            else:
                assert "13800138000" in text and "private@example.com" in text
                assert [d["name"] for d in docs] == ["report.txt", "report(1).txt", "摘要.md"]
                assert rag.models.RedactionRecord.select().count() == 0
            unsafe = zip_upload([("ok.txt", "public"), ("../private-13800138000.txt", "raw")]).read()
            rejected = await client.post(url, headers=headers, files=[("file", ("plain.txt", b"plain")), ("file", ("bad.zip", unsafe))])
            assert rejected.json() == {"code": RetCode.ARGUMENT_ERROR, "message": "ZIP_UNSAFE_PATH"}
            assert rag.models.Document.select().count() == 3
            assert len([p for p in object_dir.rglob("*") if p.is_file()]) == 3
            print(
                json.dumps(
                    {
                        "test": "ZIP_LOCAL_HTTP",
                        "redaction": protected == "1",
                        "uploaded_documents": len(docs),
                        "disk_objects": len(objects),
                        "response_code": result["code"],
                        "unsafe_zip_code": rejected.json()["code"],
                        "receipt_count": rag.models.RedactionRecord.select().count(),
                    }
                )
            )
    finally:
        shutdown.set()
        await asyncio.wait_for(server, timeout=10)
