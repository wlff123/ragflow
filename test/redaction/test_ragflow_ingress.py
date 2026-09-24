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
import sys
import types
from pathlib import Path
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

    document_service = SimpleNamespace(model=models.Document, get_by_id=get_by_id, check_doc_health=lambda *a: None, query=lambda **kw: [])
    file_service = SimpleNamespace(
        model=models.File,
        get_root_folder=lambda u: {"id": "root"},
        init_knowledgebase_docs=lambda *a: None,
        get_kb_folder=lambda u: {"id": "kb-root"},
        new_a_file_from_kb=lambda *a: {"id": "folder"},
        get_parser=lambda *a: "naive",
    )
    filetype = SimpleNamespace(OTHER=SimpleNamespace(value="other"), PDF=SimpleNamespace(value="pdf"))
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
        duplicate_name=lambda q, **kw: kw["name"],
        filename_type=lambda name: "doc",
        FileType=filetype,
        thumbnail_img=lambda *a: None,
        Path=Path,
        get_uuid=lambda: uuid4().hex,
        xxhash=SimpleNamespace(xxh128=lambda blob: hashlib.md5(blob)),
        logger=logging.getLogger("redaction-test"),
    )
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
