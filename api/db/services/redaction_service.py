"""Small RAGFlow adapter for the standalone redaction module."""

import os

from common.enterprise_redaction import RedactionError, enabled


def verify_document(doc_id, tenant_id=None, kb_id=None, bucket=None, name=None):
    if not enabled():
        return
    from api.db.db_models import DB, Document, File, File2Document, Knowledgebase, RedactionRecord
    from common import settings
    from common.enterprise_redaction.engine import validate_text_fields, verify_receipt

    try:
        with DB.connection_context():
            doc = Document.get_by_id(doc_id)
            kb = Knowledgebase.get_by_id(doc.kb_id)
            validate_text_fields(doc.parser_config)
            if kb.parser_config != doc.parser_config:
                validate_text_fields(kb.parser_config)
            links = list(File2Document.select().where(File2Document.document_id == doc_id))
            if len(links) != 1:
                raise RedactionError("REDACTION_FILE_LINK_INVALID")
            file = File.get_by_id(links[0].file_id)
            if file.source_type != "knowledgebase" or file.location != doc.location or file.name != doc.name or file.tenant_id != kb.tenant_id:
                raise RedactionError("REDACTION_FILE_LINK_INVALID")
            actual_bucket, actual_name = doc.kb_id, doc.location
            if (tenant_id is not None and str(tenant_id) != str(kb.tenant_id)) or (kb_id is not None and str(kb_id) != str(kb.id)):
                raise RedactionError("REDACTION_DOCUMENT_SCOPE_MISMATCH")
            if (bucket is not None and bucket != actual_bucket) or (name is not None and name != actual_name):
                raise RedactionError("REDACTION_STORAGE_ADDRESS_MISMATCH")
            if doc.location != doc.name:
                raise RedactionError("REDACTION_STORAGE_ADDRESS_MISMATCH")
            receipt = RedactionRecord.get_by_id(doc_id).receipt
            blob = settings.STORAGE_IMPL.get(actual_bucket, actual_name, kb.tenant_id)
            verify_receipt(receipt, doc.id, kb.tenant_id, kb.id, doc.name, blob)
    except RedactionError:
        raise
    except Exception:
        raise RedactionError("REDACTION_DOCUMENT_UNVERIFIED") from None


def verify_task(task):
    if not enabled():
        return
    # Debug uploads, memory tasks, replays and library-wide compilation need
    # separate ingress contracts; do not silently let them bypass this pilot.
    if task.get("file") is not None or task.get("task_type", "") not in {"", "naive", "dataflow"}:
        raise RedactionError("REDACTION_TASK_UNSUPPORTED")
    verify_document(task.get("doc_id"), task.get("tenant_id"), task.get("kb_id"))


def validate_startup():
    if not enabled():
        return
    from api.db.db_models import DB, Document, File, File2Document
    from common.enterprise_redaction.engine import get_engine

    if os.environ.get("RAGFLOW_REDACTION_ISOLATED") != "1":
        raise RedactionError("REDACTION_REQUIRES_ISOLATED_INSTANCE")
    get_engine()  # Fail startup if policy/key/SDK is missing. Never fall back.
    with DB.connection_context():
        doc_ids = [doc.id for doc in Document.select(Document.id)]
    for doc_id in doc_ids:
        verify_document(doc_id)
    with DB.connection_context():
        # Linked files were checked above; only orphan files remain to audit.
        linked_files = File2Document.select(File2Document.file_id).join(Document, on=(File2Document.document_id == Document.id))
        if File.select().where(File.type != "folder", File.id.not_in(linked_files)).exists():
            raise RedactionError("REDACTION_EXISTING_FILE_UNVERIFIED")
