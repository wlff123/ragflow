"""Opt-in HTTP smoke test. Run ONLY against a dedicated redaction instance.

Creates a test user/dataset and three synthetic documents; keeps them for review.
Run from the RAGFlow environment so conf/public.pem and Cryptodome are available.
"""

import argparse
import json
import time
from pathlib import Path
from uuid import uuid4

import requests

from api.utils.crypt import crypt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--embedding-url", required=True)
    parser.add_argument("--embedding-model", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    session = requests.Session()
    session.trust_env = False
    base = args.base_url.rstrip("/") + "/api/v1"
    evidence = {"base_url": args.base_url, "checks": [], "documents": []}

    def call(method, path, **kwargs):
        response = session.request(method, base + path, timeout=60, **kwargs)
        response.raise_for_status()
        body = response.json()
        assert body["code"] == 0, (method, path, body.get("message"))
        return response, body.get("data")

    def passed(name):
        evidence["checks"].append(name)
        print(name, flush=True)
        Path(args.output).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")

    # Refuse to run against an ordinary instance: unknown writes must be blocked.
    assert session.post(base + "/files", timeout=10).status_code == 403
    response, user = call("POST", "/users", json={"email": f"redaction-{uuid4().hex[:12]}@example.com", "nickname": "脱敏验证", "password": crypt(uuid4().hex)})
    session.headers["Authorization"] = response.headers["Authorization"]
    passed("HTTP account and authentication")
    provider = "OpenAI-API-Compatible"
    call("PUT", "/providers", json={"provider_name": provider})
    call(
        "POST",
        f"/providers/{provider}/instances",
        json={
            "instance_name": "redaction-validation",
            "api_key": "local-validation",
            "base_url": args.embedding_url,
            "model_info": [{"model_type": ["embedding"], "model_name": args.embedding_model, "max_tokens": 512}],
        },
    )
    _, models = call("GET", "/models?type=embedding")
    model = next(m for m in models if m["instance_name"] == "redaction-validation")
    call("PATCH", "/models/default", json={"model_type": "embedding", "model_id": model["model_id"]})
    _, kb = call(
        "POST",
        "/datasets",
        json={
            "name": "Presidio入库前脱敏验证",
            "embedding_model": model["model_id"],
            "chunk_method": "naive",
            "parse_type": 1,
            "parser_config": {"layout_recognize": "Plain Text", "chunk_token_num": 128, "auto_keywords": 0, "auto_questions": 0},
        },
    )
    kb_id = kb["id"]
    evidence["dataset_id"] = kb_id
    passed("Local embedding and dataset configured")
    secrets = ["13800138000", "demo@example.com", "11010519491231002X", "星桥机密项目", "sk-test-ABCDEF1234567890"]
    sources = [
        ("13800138000-原始.txt", "项目预算为42万元。电话13800138000，邮箱demo@example.com，身份证11010519491231002X，星桥机密项目，密钥sk-test-ABCDEF1234567890。"),
        ("原始.md", "# 项目预算\n\n预算42万元，联系人13800138000。\n\n[文档入口](https://example.com/private?token=secret)"),
        ("原始.csv", "手机号13800138000,项目预算,备注\n13800138000,42万元,星桥机密项目\n"),
    ]
    doc_ids = []
    for name, text in sources:
        _, docs = call("POST", f"/datasets/{kb_id}/documents", files={"file": (name, text.encode("utf-8"))})
        doc = docs[0]
        doc_id = doc["id"]
        doc_ids.append(doc_id)
        download = session.get(base + f"/datasets/{kb_id}/documents/{doc_id}", timeout=30)
        download.raise_for_status()
        safe = download.content.decode("utf-8")
        assert all(secret not in safe for secret in secrets)
        assert "42万元" in safe and "[已剔除]" in safe
        assert all(secret not in json.dumps(doc, ensure_ascii=False) for secret in secrets)
        evidence["documents"].append({"id": doc_id, "name": doc["name"], "safe_download": safe})
    passed("TXT Markdown CSV: safe files downloadable; original values and filenames absent")
    probes = [
        ("POST", "/files"),
        ("POST", "/documents/upload"),
        ("POST", "/files/link-to-datasets"),
        ("POST", f"/datasets/{kb_id}/documents?type=web"),
        ("POST", f"/datasets/{kb_id}/documents?type=empty"),
        ("POST", f"/datasets/{kb_id}/documents/{doc_ids[0]}/chunks"),
        ("PATCH", f"/datasets/{kb_id}/documents/{doc_ids[0]}"),
        ("PUT", f"/datasets/{kb_id}/artifacts/wiki/test"),
    ]
    for method, path in probes:
        response = session.request(method, base + path, json={"content": "13800138000"}, timeout=10)
        assert response.status_code == 403, (method, path, response.status_code)
    response = session.post(base + f"/datasets/{kb_id}/documents", files={"file": ("unsupported.pdf", b"13800138000")}, timeout=10)
    assert response.status_code == 400 and "FILE_FORMAT_UNSUPPORTED" in response.json()["message"]
    passed("Unsupported formats and eight write bypasses blocked")
    call("POST", f"/datasets/{kb_id}/documents/parse", json={"document_ids": doc_ids})
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        _, listing = call("GET", f"/datasets/{kb_id}/documents")
        docs = [d for d in listing["docs"] if d["id"] in doc_ids]
        assert all(d.get("run") not in {"FAIL", "4"} for d in docs), [(d.get("run"), d.get("progress_msg")) for d in docs]
        if len(docs) == 3 and all(d.get("chunk_count", 0) > 0 and d.get("progress", 0) >= 1 for d in docs):
            break
        time.sleep(2)
    else:
        raise AssertionError("Parsing did not complete within 300 seconds")
    for doc_id in doc_ids:
        _, chunks = call("GET", f"/datasets/{kb_id}/documents/{doc_id}/chunks")
        assert chunks["chunks"]
        assert all(secret not in json.dumps(chunks, ensure_ascii=False) for secret in secrets)
    passed("Real worker parsing and indexed chunks contain no test secrets")
    _, result = call("POST", "/retrieval", json={"dataset_ids": [kb_id], "question": "项目预算", "similarity_threshold": 0.0, "vector_similarity_weight": 0.0})
    assert result["chunks"]
    assert all(secret not in json.dumps(result, ensure_ascii=False) for secret in secrets)
    evidence["retrieved_chunks"] = len(result["chunks"])
    passed("Real retrieval returns sanitized content")
    evidence["passed"] = True
    Path(args.output).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
