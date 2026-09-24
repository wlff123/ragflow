"""Follow live_smoke.py on the SAME isolated instance; restore bytes in finally."""

import argparse
import json
from pathlib import Path

import requests

from common import settings
from common.enterprise_redaction import RedactionError, enabled


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--base-url", required=True)
    args = parser.parse_args()
    assert enabled()
    settings.init_settings()
    from api.db.db_models import Document, File, File2Document, Knowledgebase, RedactionRecord, User
    from api.db.services.redaction_service import validate_startup, verify_document, verify_task
    from api.db.services.task_service import queue_tasks

    path = Path(args.report)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["passed"]
    kb = Knowledgebase.get_by_id(report["dataset_id"])
    assert kb.name == "Presidio入库前脱敏验证"
    secrets = ["13800138000", "demo@example.com", "11010519491231002X", "星桥机密项目", "sk-test-ABCDEF1234567890"]
    for item in report["documents"]:
        doc = Document.get_by_id(item["id"])
        assert doc.kb_id == kb.id
        link = File2Document.get(File2Document.document_id == doc.id)
        rows = [doc.to_dict(), File.get_by_id(link.file_id).to_dict(), RedactionRecord.get_by_id(doc.id).to_dict()]
        assert all(secret not in json.dumps(rows, ensure_ascii=False, default=str) for secret in secrets)
        verify_document(doc.id, kb.tenant_id, kb.id)
    validate_startup()
    report["checks"].append("Actual MySQL records, signed receipts, object hashes and startup audit verified")

    doc = Document.get_by_id(report["documents"][0]["id"])
    original = settings.STORAGE_IMPL.get(kb.id, doc.location, kb.tenant_id)
    before = (doc.run, doc.progress, doc.chunk_num)
    session = requests.Session()
    session.trust_env = False
    session.headers["Authorization"] = User.get_by_id(doc.created_by).get_id()
    try:
        settings.STORAGE_IMPL.put(kb.id, doc.location, b"tampered 13800138000", kb.tenant_id)
        for check in [
            lambda: verify_document(doc.id),
            lambda: verify_task({"doc_id": doc.id, "tenant_id": kb.tenant_id, "kb_id": kb.id}),
            lambda: queue_tasks(doc.to_dict(), kb.id, doc.location, 0),
        ]:
            try:
                check()
            except RedactionError as error:
                assert str(error) == "REDACTION_RECEIPT_INVALID"
            else:
                raise AssertionError("Tampered object was accepted")
        result = session.post(args.base_url.rstrip("/") + f"/api/v1/datasets/{kb.id}/documents/parse", json={"document_ids": [doc.id]}, timeout=30)
        assert result.json()["code"] != 0
        after = Document.get_by_id(doc.id)
        assert (after.run, after.progress, after.chunk_num) == before
        report["checks"].append("Tampered object rejected by API, queue and worker validator; parsed state preserved")
    finally:
        settings.STORAGE_IMPL.put(kb.id, doc.location, original, kb.tenant_id)
    verify_document(doc.id)
    report["checks"].append("Original sanitized object restored and reverified")
    report["integrity_passed"] = True
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("MySQL/object/receipt integrity and tamper rejection: passed", flush=True)


if __name__ == "__main__":
    main()
