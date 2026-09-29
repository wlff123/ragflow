"""Bounded, in-memory ZIP expansion; independent of storage and redaction."""

import io
import stat
import threading
import unicodedata
import zipfile
from pathlib import PurePosixPath

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 1000
MAX_RATIO = 200
_slots = threading.BoundedSemaphore(2)


class ZipUploadError(ValueError):
    """Fixed error codes only: archive names and contents may be sensitive."""


class _Member(io.BytesIO):
    def __init__(self, name, data):
        super().__init__(data)
        self.filename = name


def _member_name(info):
    name = info.orig_filename.replace("\\", "/")
    directory = name.endswith("/")
    parts = (name[:-1] if directory else name).split("/")
    if (
        len(name) > 1024
        or len(parts) > 16
        or any(part in {"", ".", ".."} or ":" in part for part in parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
        or len(parts[-1].encode("utf-8")) > 255
    ):
        raise ZipUploadError("ZIP_UNSAFE_PATH")
    kind = stat.S_IFMT(info.external_attr >> 16)
    if kind not in {0, stat.S_IFDIR if directory else stat.S_IFREG}:
        raise ZipUploadError("ZIP_SPECIAL_FILE_UNSUPPORTED")
    return name, directory


def expand_zip_uploads(file_objs, *, is_supported, max_files=100, max_file_bytes=20 * 1024 * 1024, max_total_bytes=100 * 1024 * 1024):
    """Flatten ZIP members into uploads, completing checks before any writes.

    Ordinary uploads retain their original objects and stream positions. ZIP
    member basenames reuse the caller's existing format and collision handling.
    No ZIP means no new limits or imports of optional redaction dependencies.
    """
    sources = list(file_objs)
    if not any(PurePosixPath(source.filename or "").suffix.lower() == ".zip" for source in sources):
        return sources
    if len(sources) > max_files:
        raise ZipUploadError("ZIP_FILE_COUNT_LIMIT")
    if not _slots.acquire(blocking=False):
        raise ZipUploadError("ZIP_BUSY")
    try:
        expanded = []
        total_bytes = 0
        for source in sources:
            if PurePosixPath(source.filename or "").suffix.lower() != ".zip":
                expanded.append(source)
            else:
                if hasattr(source, "id") or hasattr(source, "fingerprint"):
                    raise ZipUploadError("ZIP_OVERWRITE_OR_CONNECTOR_UNSUPPORTED")
                raw = source.read(MAX_ARCHIVE_BYTES + 1)
                if len(raw) > MAX_ARCHIVE_BYTES:
                    raise ZipUploadError("ZIP_ARCHIVE_SIZE_LIMIT")
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    if len(archive.infolist()) > MAX_ENTRIES:
                        raise ZipUploadError("ZIP_ENTRY_COUNT_LIMIT")
                    seen = set()
                    file_count = 0
                    for info in archive.infolist():
                        name, directory = _member_name(info)
                        key = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
                        if key in seen:
                            raise ZipUploadError("ZIP_DUPLICATE_PATH")
                        seen.add(key)
                        if info.flag_bits & 1:
                            raise ZipUploadError("ZIP_ENCRYPTED_UNSUPPORTED")
                        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                            raise ZipUploadError("ZIP_COMPRESSION_UNSUPPORTED")
                        if directory:
                            if info.file_size:
                                raise ZipUploadError("ZIP_INVALID_DIRECTORY")
                            continue
                        filename = name.rsplit("/", 1)[-1]
                        if PurePosixPath(filename).suffix.lower() == ".zip":
                            raise ZipUploadError("ZIP_NESTED_UNSUPPORTED")
                        if not is_supported(filename):
                            raise ZipUploadError("ZIP_MEMBER_FORMAT_UNSUPPORTED")
                        if len(expanded) >= max_files:
                            raise ZipUploadError("ZIP_FILE_COUNT_LIMIT")
                        if info.file_size > max_file_bytes:
                            raise ZipUploadError("ZIP_MEMBER_SIZE_LIMIT")
                        if info.file_size > MAX_RATIO * max(info.compress_size, 1):
                            raise ZipUploadError("ZIP_COMPRESSION_RATIO_LIMIT")
                        remaining = max_total_bytes - total_bytes
                        if info.file_size > remaining:
                            raise ZipUploadError("ZIP_TOTAL_SIZE_LIMIT")
                        with archive.open(info) as stream:
                            data = stream.read(min(max_file_bytes, remaining) + 1)
                        if len(data) != info.file_size:
                            raise ZipUploadError("ZIP_MEMBER_SIZE_INVALID")
                        total_bytes += len(data)
                        file_count += 1
                        expanded.append(_Member(filename, data))
                    if not file_count:
                        raise ZipUploadError("ZIP_EMPTY")
            if len(expanded) > max_files:
                raise ZipUploadError("ZIP_FILE_COUNT_LIMIT")
        return expanded
    except ZipUploadError:
        raise
    except Exception:
        raise ZipUploadError("ZIP_INVALID") from None
    finally:
        _slots.release()
