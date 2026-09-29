"""Opt-in ZIP acceptance test against a dedicated full RAGFlow deployment.

Run inside its application container. Creates synthetic datasets and retains
them for inspection. Requires real MySQL, MinIO, workers and an embedding model.
Never run against a production instance. Credentials are read from a local file.
"""

import argparse
import io
import json
import stat
import time
import zipfile
from pathlib import Path
from uuid import uuid4

import requests

from api.utils.crypt import crypt
from common import settings
from common.enterprise_redaction import enabled


def archive(members, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as output:
        for name, content in members:
            output.writestr(name, content)
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["normal", "protected"], required=True)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--embedding-url", default="http://10.253.242.1:18191/v1")
    args = parser.parse_args()
    protected = args.mode == "protected"
    assert enabled() == protected, "Wrong target mode"
    settings.init_settings()
    from api.db.db_models import DB, Document, File, File2Document, Knowledgebase, RedactionRecord
    from api.db.services.redaction_service import validate_startup, verify_document

    base = "http://127.0.0.1:9380/api/v1"
    session = requests.Session()
    session.trust_env = False
    report = {"mode": args.mode, "checks": [], "documents": [], "passed": False}
    start = time.monotonic()

    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    def passed(name, **details):
        report["checks"].append({"name": name, **details})
        save()
        print("PASS", name, flush=True)

    def call(method, path, **kwargs):
        response = session.request(method, base + path, timeout=60, **kwargs)
        response.raise_for_status()
        body = response.json()
        assert body["code"] == 0, (path, body.get("message"))
        return response, body.get("data")

    if args.credentials.exists():
        credentials = json.loads(args.credentials.read_text())
        response, _ = call("POST", "/auth/login", json={"email": credentials["email"], "password": crypt(credentials["password"])})
    else:
        assert not protected, "Protected instance requires existing test credentials"
        credentials = {"email": f"zip-{uuid4().hex[:12]}@example.com", "password": uuid4().hex}
        response, _ = call("POST", "/users", json={**credentials, "password": crypt(credentials["password"]), "nickname": "ZIP验收"})
        args.credentials.write_text(json.dumps(credentials))
        args.credentials.chmod(0o600)
    session.headers["Authorization"] = response.headers["Authorization"]
    _, models = call("GET", "/models?type=embedding")
    if not models:
        provider = "OpenAI-API-Compatible"
        call("PUT", "/providers", json={"provider_name": provider})
        call(
            "POST",
            f"/providers/{provider}/instances",
            json={
                "instance_name": "zip-validation",
                "api_key": "local-validation",
                "base_url": args.embedding_url,
                "model_info": [{"model_type": ["embedding"], "model_name": "/models", "max_tokens": 512}],
            },
        )
        _, models = call("GET", "/models?type=embedding")
    model_id = models[0]["model_id"]
    _, kb = call(
        "POST",
        "/datasets",
        json={
            "name": f"ZIP{'逐文件脱敏' if protected else '批量入库'}验收-{time.strftime('%m%d-%H%M%S')}",
            "embedding_model": model_id,
            "chunk_method": "naive",
            "parse_type": 1,
            "parser_config": {"layout_recognize": "Plain Text", "chunk_token_num": 128, "auto_keywords": 0, "auto_questions": 0},
        },
    )
    kb_id = kb["id"]
    report.update(dataset_id=kb_id, dataset_name=kb["name"], embedding_model_id=model_id)
    passed("Authenticated real API and created dataset")

    def state():
        with DB.connection_context():
            counts = {m.__name__: m.select().count() for m in (Document, File, File2Document, RedactionRecord)}
            counts["dataset_doc_num"] = Knowledgebase.get_by_id(kb_id).doc_num
        client = settings.STORAGE_IMPL.conn
        counts["objects"] = sorted((b.name, o.object_name, o.etag) for b in client.list_buckets() for o in client.list_objects(b.name, recursive=True))
        return counts

    secrets = ["13800138000", "demo@example.com", "11010519491231002X", "星桥机密项目", "sk-test-ABCDEF1234567890"]
    text = "星港项目预算42万元，已完成需求评审。电话13800138000，邮箱demo@example.com，身份证11010519491231002X，星桥机密项目，密钥sk-test-ABCDEF1234567890。"
    members = [
        ("部门甲/报告.txt", text),
        ("部门乙/报告.txt", text + "下一阶段开展上线验收。"),
        ("概览.md", "# 星港项目\n\n" + text),
        ("数据.csv", "项目,预算,联系人\n星港项目,42万元,13800138000\n"),
    ]
    payload = archive(members, zipfile.ZIP_DEFLATED)
    before = state()
    _, docs = call("POST", f"/datasets/{kb_id}/documents", files=[("file", ("资料.ZIP", payload)), ("file", ("补充.txt", text.encode()))])
    assert len(docs) == 5 and len({d["id"] for d in docs}) == 5
    after = state()
    assert after["Document"] - before["Document"] == 5
    assert after["File2Document"] - before["File2Document"] == 5
    assert after["RedactionRecord"] - before["RedactionRecord"] == (5 if protected else 0)
    assert len(after["objects"]) - len(before["objects"]) == 5
    if not protected:
        assert {d["name"] for d in docs} == {"报告.txt", "报告(1).txt", "概览.md", "数据.csv", "补充.txt"}
    originals = [t.encode() for _, t in members] + [text.encode()]
    downloads = []
    for doc in docs:
        response = session.get(base + f"/datasets/{kb_id}/documents/{doc['id']}", timeout=30)
        response.raise_for_status()
        blob = response.content
        downloads.append(blob)
        if protected:
            assert all(s not in blob.decode() for s in secrets) and "[已剔除]" in blob.decode()
            assert all(s not in json.dumps(doc, ensure_ascii=False) for s in secrets)
            verify_document(doc["id"])
        else:
            assert blob in originals
        with DB.connection_context():
            stored = Document.get_by_id(doc["id"])
            location = stored.location
        assert settings.STORAGE_IMPL.get(kb_id, location) == blob
        report["documents"].append({"id": doc["id"], "name": doc["name"], "download": blob.decode()})
    if not protected:
        assert sorted(downloads) == sorted(originals)
    passed("ZIP plus ordinary upload: 5 documents, 5 real objects, downloads and receipts verified", receipt_count=5 if protected else 0)

    symlink = zipfile.ZipInfo("link.txt")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    corrupt = bytearray(archive([("bad.txt", b"UNIQUE_CRC_PAYLOAD")]))
    corrupt[corrupt.index(b"UNIQUE_CRC_PAYLOAD")] ^= 1
    cases = [
        ("path traversal", archive([("../bad.txt", "unsafe")]), "ZIP_UNSAFE_PATH"),
        ("nested archive", archive([("nested.zip", payload)]), "ZIP_NESTED_UNSUPPORTED"),
        ("symlink", archive([(symlink, "outside")]), "ZIP_SPECIAL_FILE_UNSUPPORTED"),
        ("CRC corruption", bytes(corrupt), "ZIP_INVALID"),
        ("truncated archive", payload[:40], "ZIP_INVALID"),
        ("empty archive", archive([]), "ZIP_EMPTY"),
        ("unsupported member", archive([("test.exe", "unsafe")]), "ZIP_MEMBER_FORMAT_UNSUPPORTED"),
        ("case duplicate", archive([("a.txt", "one"), ("A.txt", "two")]), "ZIP_DUPLICATE_PATH"),
        ("compression bomb", archive([("large.txt", b"a" * 100000)], zipfile.ZIP_DEFLATED), "ZIP_COMPRESSION_RATIO_LIMIT"),
        ("count limit", archive([(f"{i}.txt", "test") for i in range(6 if protected else 101)]), "ZIP_FILE_COUNT_LIMIT"),
    ]
    if protected:
        cases.extend(
            [
                ("non-UTF8 member", archive([("ok.txt", text), ("bad.txt", b"\xff\xfe\xfa")]), "REDACTION_UTF8_REQUIRED"),
                ("protected format limit", archive([("ok.txt", text), ("bad.pdf", b"%PDF-1.7")]), "FILE_FORMAT_UNSUPPORTED"),
            ]
        )
    for name, raw, error in cases:
        before = state()
        response = session.post(base + f"/datasets/{kb_id}/documents", files=[("file", ("普通.txt", text.encode())), ("file", ("bad.zip", raw))], timeout=60)
        body = response.json()
        assert body["code"] != 0 and error in body.get("message", ""), (name, response.status_code, body)
        assert state() == before, name
        passed("Rejected without database or object changes: " + name, http_status=response.status_code, message=body["message"])

    ids = [d["id"] for d in docs]
    parse_start = time.monotonic()
    call("POST", f"/datasets/{kb_id}/documents/parse", json={"document_ids": ids})
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        _, listing = call("GET", f"/datasets/{kb_id}/documents")
        current = [d for d in listing["docs"] if d["id"] in ids]
        assert all(str(d.get("run")) not in {"FAIL", "4"} for d in current), [(d.get("run"), d.get("progress_msg")) for d in current]
        if len(current) == 5 and all(d.get("chunk_count", 0) > 0 and d.get("progress", 0) >= 1 for d in current):
            break
        time.sleep(3)
    else:
        raise AssertionError("Worker did not finish within 600 seconds")
    chunk_count = 0
    for doc in docs:
        _, chunks = call("GET", f"/datasets/{kb_id}/documents/{doc['id']}/chunks")
        assert chunks["chunks"]
        chunk_count += len(chunks["chunks"])
        serialized = json.dumps(chunks, ensure_ascii=False)
        assert "42万元" in serialized
        if protected:
            assert all(s not in serialized for s in secrets)
    passed("Real workers parsed all 5 documents; indexed chunks verified", chunks=chunk_count, seconds=round(time.monotonic() - parse_start, 2))
    for weight in [0.0, 0.5, 1.0]:
        _, result = call("POST", "/retrieval", json={"dataset_ids": [kb_id], "question": "星港项目预算", "similarity_threshold": 0, "vector_similarity_weight": weight})
        assert result["chunks"]
        serialized = json.dumps(result, ensure_ascii=False)
        assert "42万元" in serialized
        if protected:
            assert all(s not in serialized for s in secrets)
        passed("Real retrieval", vector_weight=weight, chunks=len(result["chunks"]))
    if protected:
        validate_startup()
        passed("Startup audit verifies new and existing stored documents")
    report.update(passed=True, elapsed_seconds=round(time.monotonic() - start, 2))
    save()


if __name__ == "__main__":
    main()
