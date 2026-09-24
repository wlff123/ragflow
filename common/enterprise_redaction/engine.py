"""Local Presidio rules; no model downloads, remote calls or raw-text logging."""

import csv
import hashlib
import hmac
import io
import json
import os
import re
import threading
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from uuid import uuid4

import regex
from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerRegistry, RecognizerResult
from presidio_analyzer.nlp_engine import NoOpNlpEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from common.enterprise_redaction import RedactionError

MAX_BYTES = 2 * 1024 * 1024
MAX_CHARS = 200_000
MAX_FILES = 5
MAX_CSV_ROWS = 10_000
MAX_CSV_COLUMNS = 256
MAX_CSV_CELLS = 20_000
IMPLEMENTATION = "rules-v3-presidio-2.2.364"
REGEX_TIMEOUT_SECONDS = 1
# At most five rules: bound Presidio's quadratic deduplication/conflict handling.
MAX_MATCHES_PER_RULE = 200
_slots = threading.BoundedSemaphore(2)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Policy:
    terms: tuple[str, ...]
    key: bytes

    @property
    def digest(self):
        # Bump implementation version on ANY rule/extractor/SDK change.
        return hashlib.sha256(canonical({"implementation": IMPLEMENTATION, "terms": self.terms})).hexdigest()


@lru_cache(maxsize=1)
def load_policy():
    try:
        config = json.loads(Path(os.environ["RAGFLOW_REDACTION_POLICY"]).read_text(encoding="utf-8"))
        key = bytes.fromhex(os.environ["RAGFLOW_REDACTION_HMAC_KEY"])
        if set(config) != {"business_terms"} or len(key) < 32:
            raise ValueError
        terms = config["business_terms"]
        if not isinstance(terms, list) or len(terms) > 1000:
            raise ValueError
        if any(not isinstance(t, str) or not 2 <= len(t) <= 128 or "\x00" in t for t in terms):
            raise ValueError
        return Policy(tuple(sorted(set(terms))), key)
    except Exception:
        raise RedactionError("REDACTION_INVALID_POLICY") from None


class _RuleRecognizer(EntityRecognizer):
    """Use Presidio's public extension API; PatternRecognizer swallows timeouts."""

    def __init__(self, entity, pattern):
        self.pattern = regex.compile(pattern, regex.DOTALL | regex.MULTILINE | regex.IGNORECASE)
        super().__init__(supported_entities=[entity], supported_language="zh", name=entity)

    def load(self):
        pass

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []
        try:
            for match in self.pattern.finditer(text, timeout=REGEX_TIMEOUT_SECONDS):
                if len(results) >= MAX_MATCHES_PER_RULE:
                    raise RedactionError("REDACTION_MATCH_LIMIT")
                if match.groupdict().get("unclosed_quote"):
                    raise RedactionError("REDACTION_SECRET_SYNTAX_INVALID")
                results.append(RecognizerResult(self.supported_entities[0], match.start(), match.end(), 0.8))
        except TimeoutError:
            raise RedactionError("REDACTION_RULE_TIMEOUT") from None
        return results


class Engine:
    def __init__(self, policy):
        from importlib.metadata import version

        if any(version(p) != "2.2.364" for p in ("presidio-analyzer", "presidio-anonymizer")):
            raise RedactionError("REDACTION_SDK_VERSION_MISMATCH")
        secret_key = r"(?:api[_-]?key|access[_-]?token|password|secret)"
        rules = {
            "CN_MOBILE": r"(?<!\d)(?:\+?86[- ]?)?1[3-9]\d(?:[- ]?\d{4}){2}(?!\d)",
            # Conservatively redact ID-shaped strings, including invalid checksums.
            "CN_ID": r"(?<![0-9A-Za-z])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9A-Za-z])",
            "EMAIL_ADDRESS": r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
            "ACCESS_SECRET": (
                r"(?i)(?<![A-Za-z0-9_])(?:sk-[A-Za-z0-9_-]{12,}|"
                rf"(?:\"{secret_key}\"|'{secret_key}'|{secret_key})\s*[:=]\s*"
                r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|(?P<unclosed_quote>["'])|[^\s"',;<>，；。{}\[\]]+))"""
            ),
        }
        if policy.terms:
            rules["BUSINESS_TERM"] = "|".join(re.escape(term) for term in sorted(policy.terms, key=len, reverse=True))
        recognizers = [_RuleRecognizer(name, pattern) for name, pattern in rules.items()]
        self.analyzer = AnalyzerEngine(
            registry=RecognizerRegistry(supported_languages=["zh"], recognizers=recognizers),
            nlp_engine=NoOpNlpEngine(models=[{"lang_code": "zh", "model_name": ""}]),
            supported_languages=["zh"],
            log_decision_process=False,
        )
        self.anonymizer = AnonymizerEngine()
        self.entities = list(rules)

    def redact(self, text):
        hits = self.analyzer.analyze(text=text, language="zh", entities=self.entities, score_threshold=0.5)
        counts = Counter(hit.entity_type for hit in hits)
        # Union overlaps, so a shorter high-score hit cannot expose a longer secret.
        spans = []
        for hit in sorted(hits, key=lambda x: (x.start, x.end)):
            if spans and hit.start < spans[-1][1]:
                spans[-1][1] = max(spans[-1][1], hit.end)
            else:
                spans.append([hit.start, hit.end])
        merged = [RecognizerResult("SENSITIVE", start, end, 1.0) for start, end in spans]
        output = self.anonymizer.anonymize(
            text=text,
            analyzer_results=merged,
            operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[已剔除]"})},
            merge_entities_with_spaces=False,
        ).text
        return output, counts


@lru_cache(maxsize=1)
def get_engine():
    try:
        return Engine(load_policy())
    except RedactionError:
        raise
    except Exception:
        raise RedactionError("REDACTION_ENGINE_UNAVAILABLE") from None


def validate_text_fields(value):
    """Reject sensitive configuration without silently changing its semantics."""
    try:
        # Check both serialized key/value pairs (e.g. password fields) and
        # decoded strings (JSON escaping must not hide business terms).
        texts = [canonical(value).decode("utf-8")]
        if len(texts[0]) > MAX_CHARS:
            raise RedactionError("REDACTION_CONFIG_SIZE_LIMIT")

        def collect(item):
            if isinstance(item, str):
                texts.append(item)
            elif isinstance(item, dict):
                for key, child in item.items():
                    collect(key)
                    collect(child)
            elif isinstance(item, list):
                for child in item:
                    collect(child)

        collect(value)
        text = "\n".join(texts)
        if get_engine().redact(text)[0] != text:
            raise RedactionError("REDACTION_CONFIG_CONTAINS_SENSITIVE_TEXT")
    except RedactionError:
        raise
    except Exception:
        raise RedactionError("REDACTION_CONFIG_INVALID") from None


def markdown_text(text):
    from markdown_it import MarkdownIt

    if text.lstrip().startswith(("---", "+++")):
        raise RedactionError("REDACTION_MARKDOWN_FRONTMATTER_UNSUPPORTED")
    tokens = MarkdownIt("commonmark", {"html": True}).parse(text)
    output = []

    def visit(token):
        if token.type in {"image", "html_inline", "html_block"}:
            raise RedactionError("REDACTION_MARKDOWN_EMBED_UNSUPPORTED")
        if token.children:
            for child in token.children:
                visit(child)
        elif token.type in {"text", "code_inline", "code_block", "fence"}:
            output.append(token.content)
        if token.type in {"softbreak", "hardbreak", "paragraph_close", "heading_close", "fence", "code_block"}:
            output.append("\n")

    for token in tokens:
        visit(token)
    return "".join(output)


@dataclass
class PreparedFile:
    id: str
    filename: str
    blob: bytes
    receipt: dict

    def read(self):
        return self.blob


def sign(payload, key):
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


def prepare_files(file_objs, tenant_id, kb_id):
    """Pure preprocessing: complete the batch before any persistent writes."""
    if not 1 <= len(file_objs) <= MAX_FILES:
        raise RedactionError("REDACTION_FILE_COUNT_LIMIT")
    if not _slots.acquire(blocking=False):
        raise RedactionError("REDACTION_BUSY")
    try:
        policy, engine = load_policy(), get_engine()
        prepared = []
        for source in file_objs:
            if hasattr(source, "id") or hasattr(source, "fingerprint"):
                raise RedactionError("REDACTION_OVERWRITE_OR_CONNECTOR_UNSUPPORTED")
            suffix = Path(source.filename or "").suffix.lower()
            if suffix not in {".txt", ".md", ".csv"}:
                raise RedactionError("REDACTION_FILE_FORMAT_UNSUPPORTED")
            raw = source.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise RedactionError("REDACTION_FILE_SIZE_LIMIT")
            try:
                text = raw.decode("utf-8-sig", errors="strict")
            except UnicodeError:
                raise RedactionError("REDACTION_UTF8_REQUIRED") from None
            if len(text) > MAX_CHARS:
                raise RedactionError("REDACTION_TEXT_SIZE_LIMIT")
            if "\x00" in text:
                raise RedactionError("REDACTION_BINARY_CONTENT_UNSUPPORTED")
            counts = Counter()

            def redact(value):
                safe, hits = engine.redact(value)
                counts.update(hits)
                return safe

            if suffix == ".md":
                text, suffix = markdown_text(text), ".txt"
            if suffix == ".csv":
                stream = io.StringIO(newline="")
                writer = csv.writer(stream)
                width = None
                row_count = cell_count = 0
                try:
                    for row in csv.reader(io.StringIO(text, newline=""), strict=True):
                        if not row:
                            continue
                        row_count += 1
                        cell_count += len(row)
                        if row_count > MAX_CSV_ROWS or len(row) > MAX_CSV_COLUMNS or cell_count > MAX_CSV_CELLS:
                            raise RedactionError("REDACTION_CSV_SIZE_LIMIT")
                        if width is None:
                            width = len(row)
                        if len(row) != width:
                            raise RedactionError("REDACTION_CSV_SHAPE_INVALID")
                        safe_row = []
                        for cell in row:
                            safe = redact(cell)
                            if safe.lstrip().startswith(("=", "+", "-", "@")) or safe.startswith(("\t", "\r")):
                                safe = "'" + safe
                            safe_row.append(safe)
                        writer.writerow(safe_row)
                except csv.Error:
                    raise RedactionError("REDACTION_CSV_INVALID") from None
                text = stream.getvalue()
            else:
                text = redact(text)
            blob = text.encode("utf-8")
            if not blob.strip() or len(blob) > MAX_BYTES:
                raise RedactionError("REDACTION_OUTPUT_SIZE_INVALID")
            doc_id = uuid4().hex
            filename = f"文档-{doc_id}{suffix}"
            payload = dict(
                doc_id=doc_id,
                tenant_id=str(tenant_id),
                kb_id=str(kb_id),
                name=filename,
                sha256=hashlib.sha256(blob).hexdigest(),
                policy=policy.digest,
                counts=dict(counts),
                engine=IMPLEMENTATION,
            )
            prepared.append(PreparedFile(doc_id, filename, blob, {"payload": payload, "signature": sign(payload, policy.key)}))
        return prepared
    except RedactionError:
        raise
    except Exception:
        raise RedactionError("REDACTION_PREPROCESS_FAILED") from None
    finally:
        _slots.release()


def verify_receipt(receipt, doc_id, tenant_id, kb_id, name, blob):
    try:
        policy = load_policy()
        payload = receipt["payload"]
        if not hmac.compare_digest(receipt["signature"], sign(payload, policy.key)):
            raise ValueError
        expected = {"doc_id": str(doc_id), "tenant_id": str(tenant_id), "kb_id": str(kb_id), "name": name, "policy": policy.digest, "sha256": hashlib.sha256(blob).hexdigest()}
        if any(payload.get(k) != v for k, v in expected.items()):
            raise ValueError
    except Exception:
        raise RedactionError("REDACTION_RECEIPT_INVALID") from None
