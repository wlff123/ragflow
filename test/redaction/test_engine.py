import copy
import csv
import io
import json
import socket

import pytest

from common.enterprise_redaction import RedactionError, enabled
from common.enterprise_redaction import engine


def test_local_detection_no_network(upload, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("Network must not be used")

    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    raw = "😀联系人电话13800138000，邮件demo@example.com；身份证11010519491231002X；星桥机密项目；api_key=demoSECRET987654；订单202609240001。"
    result = engine.prepare_files([upload(raw, "机密13800138000.txt")], "tenant", "kb")[0]
    assert result.blob.decode() == "😀联系人电话[已剔除]，邮件[已剔除]；身份证[已剔除]；[已剔除]；[已剔除]；订单202609240001。"
    stored = json.dumps(result.receipt, ensure_ascii=False) + result.filename
    assert all(secret not in stored for secret in ["13800138000", "demo@example.com", "11010519491231002X", "星桥机密项目", "demoSECRET987654"])
    assert result.receipt["payload"]["counts"] == {"CN_MOBILE": 1, "EMAIL_ADDRESS": 1, "CN_ID": 1, "ACCESS_SECRET": 1, "BUSINESS_TERM": 1}
    engine.verify_receipt(result.receipt, result.id, "tenant", "kb", result.filename, result.blob)


def test_overlap_is_fully_removed(upload):
    result = engine.prepare_files([upload("前缀机密13800138000资料后缀")], "t", "k")[0]
    assert result.blob.decode() == "前缀[已剔除]后缀"


def test_secret_prefix_adjacent_to_chinese(upload):
    result = engine.prepare_files([upload("密钥sk-test-ABCDEF1234567890。配置api_key=abc123456；后文保留。")], "t", "k")[0]
    assert result.blob.decode() == "密钥[已剔除]。配置[已剔除]；后文保留。"


def test_markdown_links_removed_and_text_sanitized(upload):
    md = "# 标题\n[联系方式](https://example.com/?token=secret)\n\n电话13800138000\n\n```text\npassword=secret123\n```"
    result = engine.prepare_files([upload(md, "file.md")], "t", "k")[0]
    assert result.filename.endswith(".txt")
    assert "https://" not in result.blob.decode()
    assert "13800138000" not in result.blob.decode()
    assert "secret123" not in result.blob.decode()
    assert "标题" in result.blob.decode()


@pytest.mark.parametrize("text", ["![图片](x.png)", "<div>内容</div>", "---\nsecret: x\n---", "+++\nkey=x", "hello <!--secret-->"])
def test_markdown_embeds_rejected(upload, text):
    with pytest.raises(RedactionError, match="REDACTION_MARKDOWN"):
        engine.prepare_files([upload(text, "x.md")], "t", "k")


def test_csv_headers_multiline_shape_and_formulas(upload):
    result = engine.prepare_files([upload('手机号13800138000,备注\n13800138000,"两行\n星桥机密项目"\n普通值,=SUM(A1)\n', "x.csv")], "t", "k")[0]
    rows = list(csv.reader(io.StringIO(result.blob.decode())))
    assert rows == [["手机号[已剔除]", "备注"], ["[已剔除]", "两行\n[已剔除]"], ["普通值", "'=SUM(A1)"]]


@pytest.mark.parametrize(
    "raw,name,error",
    [
        (b"\xff", "x.txt", "UTF8"),
        (b"binary\x00", "x.txt", "BINARY"),
        ("x" * (engine.MAX_CHARS + 1), "x.txt", "TEXT_SIZE"),
        (b"x" * (engine.MAX_BYTES + 1), "x.txt", "FILE_SIZE"),
        ("x", "x.pdf", "FORMAT"),
        ("a,b\n1,2,3", "x.csv", "CSV_SHAPE"),
        ('a,b\n1,"oops', "x.csv", "CSV_INVALID"),
        ("   ", "x.txt", "OUTPUT_SIZE"),
    ],
    ids=["encoding", "binary", "characters", "bytes", "format", "csv-shape", "csv-syntax", "empty"],
)
def test_invalid_inputs_fail_closed(upload, raw, name, error):
    with pytest.raises(RedactionError, match=error):
        engine.prepare_files([upload(raw, name)], "t", "k")


def test_batch_and_connector_rejected(upload):
    with pytest.raises(RedactionError, match="FILE_COUNT"):
        engine.prepare_files([upload("x") for _ in range(6)], "t", "k")
    source = upload("x")
    source.id = "overwrite"
    with pytest.raises(RedactionError, match="OVERWRITE_OR_CONNECTOR"):
        engine.prepare_files([source], "t", "k")


def test_csv_work_limit(upload, monkeypatch):
    monkeypatch.setattr(engine, "MAX_CSV_CELLS", 3)
    with pytest.raises(RedactionError, match="CSV_SIZE_LIMIT"):
        engine.prepare_files([upload("a,b\nc,d", "x.csv")], "t", "k")


@pytest.mark.parametrize("field,value", [("doc_id", "other"), ("tenant_id", "other"), ("kb_id", "other"), ("name", "other.txt"), ("policy", "other"), ("counts", {})])
def test_signed_fields_cannot_be_forged(upload, field, value):
    result = engine.prepare_files([upload("13800138000")], "t", "k")[0]
    receipt = copy.deepcopy(result.receipt)
    receipt["payload"][field] = value
    with pytest.raises(RedactionError, match="RECEIPT_INVALID"):
        engine.verify_receipt(receipt, result.id, "t", "k", result.filename, result.blob)


def test_replay_and_content_tampering(upload):
    result = engine.prepare_files([upload("13800138000")], "t", "k")[0]
    for doc_id, tenant, kb, name, blob in [
        ("other", "t", "k", result.filename, result.blob),
        (result.id, "x", "k", result.filename, result.blob),
        (result.id, "t", "x", result.filename, result.blob),
        (result.id, "t", "k", "other.txt", result.blob),
        (result.id, "t", "k", result.filename, b"13800138000"),
    ]:
        with pytest.raises(RedactionError, match="RECEIPT_INVALID"):
            engine.verify_receipt(result.receipt, doc_id, tenant, kb, name, blob)


def test_policy_change_invalidates_receipt(upload, policy):
    result = engine.prepare_files([upload("ok")], "t", "k")[0]
    policy.write_text('{"business_terms": []}', encoding="utf-8")
    engine.load_policy.cache_clear()
    with pytest.raises(RedactionError, match="RECEIPT_INVALID"):
        engine.verify_receipt(result.receipt, result.id, "t", "k", result.filename, result.blob)


def test_missing_key_or_unknown_policy_never_falls_back(upload, monkeypatch, policy):
    monkeypatch.delenv("RAGFLOW_REDACTION_HMAC_KEY")
    with pytest.raises(RedactionError, match="INVALID_POLICY"):
        engine.prepare_files([upload("13800138000")], "t", "k")
    monkeypatch.setenv("RAGFLOW_REDACTION_HMAC_KEY", "ab" * 32)
    policy.write_text('{"business_terms": [], "ner_model": "unknown"}', encoding="utf-8")
    with pytest.raises(RedactionError, match="INVALID_POLICY"):
        engine.prepare_files([upload("13800138000")], "t", "k")


def test_invalid_flag_is_not_disabled(monkeypatch):
    monkeypatch.setenv("RAGFLOW_REDACTION_ENABLED", "true")
    with pytest.raises(RedactionError, match="INVALID_ENABLED_FLAG"):
        enabled()


def test_slot_limit_released_after_failure(upload):
    engine._slots.acquire()
    engine._slots.acquire()
    try:
        with pytest.raises(RedactionError, match="BUSY"):
            engine.prepare_files([upload("ok")], "t", "k")
    finally:
        engine._slots.release()
        engine._slots.release()
    assert engine.prepare_files([upload("ok")], "t", "k")


@pytest.mark.parametrize(
    "text",
    [
        '{"password": "abcDEF123456"}',
        "{'api_key': 'abc def ghi'}",
        'password="abc def ghi"',
        'password="abcd, efgh; ijkl"',
        r'password="ab\" cd"',
        'password="line one\nline two"',
        "password=x",
    ],
)
def test_quoted_and_short_secrets_removed_completely(upload, text):
    safe = engine.prepare_files([upload(text)], "t", "k")[0].blob.decode()
    assert safe.strip("{}") == "[已剔除]"


@pytest.mark.parametrize("text", ['password="abc def', "api_key='abcd", 'password="ends with escape\\'])
def test_unclosed_secret_is_rejected(upload, text):
    with pytest.raises(RedactionError, match="SECRET_SYNTAX_INVALID"):
        engine.prepare_files([upload(text)], "t", "k")


@pytest.mark.parametrize("phone", ["138-0013-8000", "138 0013 8000", "+86 138-0013-8000", "8613800138000"])
def test_formatted_mobile_removed(upload, phone):
    safe = engine.prepare_files([upload("电话" + phone + "。订单202609240001和113800138000保留")], "t", "k")[0].blob.decode()
    assert safe == "电话[已剔除]。订单202609240001和113800138000保留"


def test_pathological_email_prefix_does_not_hide_later_email(upload):
    text = "a" * 180000 + "@bad  private@example.com"
    safe = engine.prepare_files([upload(text)], "t", "k")[0].blob.decode()
    assert safe == "a" * 180000 + "@bad  [已剔除]"


def test_real_regex_timeout_is_not_swallowed(upload, monkeypatch):
    monkeypatch.setattr(engine, "REGEX_TIMEOUT_SECONDS", 1e-12)
    with pytest.raises(RedactionError, match="RULE_TIMEOUT"):
        engine.prepare_files([upload("a" * 180000 + "@bad  private@example.com")], "t", "k")


@pytest.mark.parametrize(
    "value",
    [
        {"metadata": {"contact": {"enum": ["13800138000"]}}},
        {"password": "abc def ghi"},
        {"nested": [{"星桥机密项目": "ordinary"}]},
        {"description": "星桥机密项目"},
    ],
)
def test_configuration_text_is_checked(value):
    with pytest.raises(RedactionError, match="CONFIG_CONTAINS_SENSITIVE_TEXT"):
        engine.validate_text_fields(value)


def test_safe_config_is_unchanged():
    value = {"chunk_token_num": 128, "layout_recognize": "Plain Text", "metadata": {"field": {"type": "string"}}}
    before = copy.deepcopy(value)
    engine.validate_text_fields(value)
    assert value == before


def test_business_terms_keep_case_insensitive_matching():
    rules = engine.Engine(engine.Policy(("InternalProject",), b"a" * 32))
    assert rules.redact("internalproject INTERNALPROJECT")[0] == "[已剔除] [已剔除]"


@pytest.mark.parametrize("sample", ["13800138000", "11010519491231002X", "demo@example.com", "password=abc", "星桥机密项目"])
def test_match_limit_rejects_before_quadratic_processing(sample, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Over-limit results must not reach Presidio postprocessing")

    monkeypatch.setattr(engine.EntityRecognizer, "remove_duplicates", unexpected)
    monkeypatch.setattr(engine.get_engine().anonymizer, "anonymize", unexpected)
    with pytest.raises(RedactionError, match="REDACTION_MATCH_LIMIT"):
        engine.get_engine().redact((sample + "; ") * (engine.MAX_MATCHES_PER_RULE + 1))


def test_all_rules_at_match_limit_are_fully_redacted():
    samples = ["13800138000", "11010519491231002X", "demo@example.com", "password=abc", "星桥机密项目"]
    text = "; ".join(samples) + "; "
    safe, counts = engine.get_engine().redact(text * engine.MAX_MATCHES_PER_RULE)
    assert len(counts) == len(samples)
    assert set(counts.values()) == {engine.MAX_MATCHES_PER_RULE}
    assert safe == ("[已剔除]; " * len(samples)) * engine.MAX_MATCHES_PER_RULE
