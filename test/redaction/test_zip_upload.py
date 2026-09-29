import stat
import struct
import zipfile

import pytest

from common import zip_upload as module
from common.zip_upload import ZipUploadError, expand_zip_uploads


def expand(files, **limits):
    return expand_zip_uploads(files, is_supported=lambda name: name.lower().endswith((".txt", ".md", ".csv", ".pdf", ".docx")), **limits)


def test_multiple_archives_mixed_uploads_and_chinese_paths(zip_upload, upload):
    plain = upload("plain", "loose.txt")
    packed = zip_upload([("目录/", ""), ("目录/中文.txt", "你好"), ("other/中文.txt", "other")], "BATCH.ZIP")
    results = expand([plain, packed, zip_upload([("nested\\file.md", "# Title")])])
    assert results[0] is plain
    assert [f.filename for f in results] == ["loose.txt", "中文.txt", "中文.txt", "file.md"]
    assert [f.read() for f in results] == [b"plain", "你好".encode(), b"other", b"# Title"]


def test_no_zip_does_not_read_or_add_limits(upload):
    source = upload(b"large")
    source.read(1)
    assert expand([source], max_files=0, max_file_bytes=0) == [source]
    assert source.read() == b"arge"


@pytest.mark.parametrize(
    "path",
    ["../x.txt", "/x.txt", "C:/x.txt", "C:x.txt", "a/../x.txt", "a/./x.txt", "a//x.txt", "\\\\host\\x.txt", "x.txt:stream", "a\nx.txt", "a/" * 16 + "x.txt", "中" * 86 + ".txt", "a" * 1025 + "/x.txt"],
)
def test_unsafe_paths_rejected(zip_upload, path):
    with pytest.raises(ZipUploadError, match="ZIP_UNSAFE_PATH"):
        expand([zip_upload([(path, "secret")])])


def test_nul_in_original_filename_rejected(zip_upload, upload):
    raw = zip_upload([("xQ.txt", "secret")]).read().replace(b"xQ.txt", b"x\x00.txt")
    with pytest.raises(ZipUploadError, match="ZIP_UNSAFE_PATH"):
        expand([upload(raw, "secret.zip")])


@pytest.mark.parametrize("kind", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFDIR])
def test_special_files_rejected(zip_upload, kind):
    info = zipfile.ZipInfo("link.txt")
    info.create_system = 3
    info.external_attr = (kind | 0o644) << 16
    with pytest.raises(ZipUploadError, match="ZIP_SPECIAL_FILE"):
        expand([zip_upload([(info, "target")])])


@pytest.mark.parametrize(
    "entries,code",
    [
        ([], "ZIP_EMPTY"),
        ([("folder/", "")], "ZIP_EMPTY"),
        ([("folder/", "payload")], "ZIP_INVALID_DIRECTORY"),
        ([("nested.ZIP", "payload")], "ZIP_NESTED_UNSUPPORTED"),
        ([("program.exe", "payload")], "ZIP_MEMBER_FORMAT_UNSUPPORTED"),
        ([("A.txt", "one"), ("a.txt", "two")], "ZIP_DUPLICATE_PATH"),
        ([("é.txt", "one"), ("e\u0301.txt", "two")], "ZIP_DUPLICATE_PATH"),
    ],
)
def test_invalid_archives_rejected(zip_upload, entries, code):
    with pytest.raises(ZipUploadError, match=code):
        expand([zip_upload(entries)])


def test_stored_and_office_container_are_supported(zip_upload):
    office = zip_upload([("word/document.xml", "document")]).read()
    out = expand([zip_upload([("file.docx", office)], compression=zipfile.ZIP_STORED)])
    assert out[0].read() == office


@pytest.mark.parametrize("corruption", ["crc", "truncated", "not-zip", "encrypted", "compression"])
def test_corrupted_or_encrypted_archives_fail_without_leaking_names(zip_upload, upload, corruption):
    raw = bytearray(zip_upload([("private-13800138000.txt", "ORIGINAL")], compression=zipfile.ZIP_STORED).read())
    if corruption == "crc":
        raw[raw.index(b"ORIGINAL")] ^= 1
    elif corruption == "truncated":
        raw = raw[:-25]
    elif corruption == "not-zip":
        raw = b"private data"
    else:
        local, central = raw.index(b"PK\x03\x04"), raw.index(b"PK\x01\x02")
        if corruption == "encrypted":
            struct.pack_into("<H", raw, local + 6, 1)
            struct.pack_into("<H", raw, central + 8, 1)
        else:
            struct.pack_into("<H", raw, local + 8, 99)
            struct.pack_into("<H", raw, central + 10, 99)
    with pytest.raises(ZipUploadError) as caught:
        expand([upload(bytes(raw), "13800138000.zip")])
    assert str(caught.value) == {"encrypted": "ZIP_ENCRYPTED_UNSUPPORTED", "compression": "ZIP_COMPRESSION_UNSUPPORTED"}.get(corruption, "ZIP_INVALID")


@pytest.mark.parametrize("limits,code", [({"max_files": 1}, "ZIP_FILE_COUNT_LIMIT"), ({"max_file_bytes": 2}, "ZIP_MEMBER_SIZE_LIMIT"), ({"max_total_bytes": 5}, "ZIP_TOTAL_SIZE_LIMIT")])
def test_actual_file_limits(zip_upload, limits, code):
    with pytest.raises(ZipUploadError, match=code):
        expand([zip_upload([("a.txt", "123"), ("b.txt", "456")])], **limits)


def test_aggregate_limits_across_archives_and_plain_files(zip_upload, upload):
    with pytest.raises(ZipUploadError, match="ZIP_TOTAL_SIZE_LIMIT"):
        expand([zip_upload([("a.txt", "123")]), zip_upload([("b.txt", "456")])], max_total_bytes=5)
    with pytest.raises(ZipUploadError, match="ZIP_FILE_COUNT_LIMIT"):
        expand([zip_upload([("a.txt", "1"), ("b.txt", "2")]), upload("plain")], max_files=2)


@pytest.mark.parametrize("constant,value,code", [("MAX_ARCHIVE_BYTES", 20, "ZIP_ARCHIVE_SIZE_LIMIT"), ("MAX_ENTRIES", 1, "ZIP_ENTRY_COUNT_LIMIT")])
def test_archive_limits(zip_upload, monkeypatch, constant, value, code):
    monkeypatch.setattr(module, constant, value)
    with pytest.raises(ZipUploadError, match=code):
        expand([zip_upload([("a/", ""), ("a/x.txt", "test")])])


def test_zip_bomb_and_busy_slot(zip_upload):
    with pytest.raises(ZipUploadError, match="ZIP_COMPRESSION_RATIO_LIMIT"):
        expand([zip_upload([("bomb.txt", "0" * 100_000)])])
    module._slots.acquire()
    module._slots.acquire()
    try:
        with pytest.raises(ZipUploadError, match="ZIP_BUSY"):
            expand([zip_upload([("a.txt", "x")])])
    finally:
        module._slots.release()
        module._slots.release()
    assert expand([zip_upload([("a.txt", "x")])])[0].read() == b"x"


@pytest.mark.parametrize("attribute", ["id", "fingerprint"])
def test_zip_cannot_turn_connector_or_overwrite_into_new_upload(zip_upload, attribute):
    source = zip_upload([("a.txt", "x")])
    setattr(source, attribute, "existing")
    with pytest.raises(ZipUploadError, match="ZIP_OVERWRITE_OR_CONNECTOR"):
        expand([source])


def test_forged_uncompressed_size_rejected(zip_upload, upload):
    raw = bytearray(zip_upload([("one.txt", "body")], compression=zipfile.ZIP_STORED).read())
    struct.pack_into("<I", raw, raw.index(b"PK\x01\x02") + 24, 100)
    with pytest.raises(ZipUploadError, match="ZIP_MEMBER_SIZE_INVALID"):
        expand([upload(bytes(raw), "batch.zip")])


def test_exact_limits_accepted(zip_upload):
    files = expand([zip_upload([("a.txt", "123"), ("b.txt", "456")])], max_files=2, max_file_bytes=3, max_total_bytes=6)
    assert [file.read() for file in files] == [b"123", b"456"]
