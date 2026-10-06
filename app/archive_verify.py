"""服务数据归档 ZIP 的接收方核验（纯内存、只读）。

运维在交接前把收到的归档 ZIP 交给本模块核验。核验全程在内存中进行——
**不解压到服务数据目录，不读取也不改写服务的任何现有记录与文件**，
归档是否完整可信完全由包内 ``manifest.json`` 与五类记录文件自证：

- ZIP 成员名唯一，且全部为规定的相对路径（5 个记录 JSON、``manifest.json``、
  ``originals/{doc_id}.png|.jpg``、``publications/{doc_id}/v{n}.png``）；
- ``manifest.json`` 与实际成员一一对应，逐文件 SHA-256、``file_count``
  与 ``record_counts`` 全部一致；
- 五类记录内部计数自洽，且引用关系完整：文档 ↔ 连续标注修订（每文档
  0..current_revision 不间断）、发布版本（每文档 1..N 不间断）、批次
  成员顺序（position 0..N-1 不间断，且与发布记录的 batch_id 互相印证）、
  撤回记录（与发布记录的撤回字段互相印证）；
- 原图与发布成品的实际字节摘要与记录中的 ``original_sha256`` /
  ``output_sha256`` 一致。

任何缺项、重复项、摘要错误或关系冲突都记录为一条可定位的 failure
（code + message + 定位字段），有一条即整体判失败；全部通过时结果
携带各类记录计数与通过结论。
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from typing import Any

MANIFEST_NAME = "manifest.json"
RECORD_NAMES = (
    "documents.json",
    "annotations.json",
    "publications.json",
    "publication-batches.json",
    "withdrawals.json",
)

# 核验结果中逐条列出的失败原因上限：超出部分只在 failure_count 中计数，
# 避免病态归档（如海量非法成员）撑爆响应。
MAX_FAILURES = 100

# 规定的相对路径形态：doc_id 段只允许服务生成的标识字符（不含 "."、"/"），
# 因此绝对路径、目录穿越、目录条目与上传文件名都落不到规定形态之外。
_DOC_SEGMENT = r"([0-9A-Za-z_-]{1,64})"
_ORIGINAL_RE = re.compile(rf"^originals/{_DOC_SEGMENT}\.(png|jpg)$")
_PUBLICATION_RE = re.compile(
    rf"^publications/{_DOC_SEGMENT}/v([1-9][0-9]{{0,9}})\.png$"
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

RECORD_COUNT_KEYS = (
    "documents",
    "annotation_revisions",
    "publications",
    "publication_batches",
    "withdrawals",
)

# 库内 media_type -> 归档内原图扩展名（与归档生成端同一映射）
_MEDIA_TYPE_EXT = {"image/png": ".png", "image/jpeg": ".jpg"}

# 读取 ZIP 成员时可能抛出的异常（CRC 校验失败、不支持的压缩方式、IO 错误等）
_MEMBER_READ_ERRORS = (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError)


def _classify(name: str) -> tuple[str, str | None, int | None] | None:
    """把 ZIP 成员名归类为规定的相对路径之一；不在规定之列返回 None。

    返回 ``(kind, doc_id, version)``：kind 为 manifest / records /
    original / publication；original 与 publication 另带出路径中的
    doc_id（与版本号）。
    """
    if name == MANIFEST_NAME:
        return ("manifest", None, None)
    if name in RECORD_NAMES:
        return ("records", None, None)
    m = _ORIGINAL_RE.match(name)
    if m:
        return ("original", m.group(1), None)
    m = _PUBLICATION_RE.match(name)
    if m:
        return ("publication", m.group(1), int(m.group(2)))
    return None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


class _Findings:
    """核验发现收集器：逐条记录可定位的失败原因（总数可超过返回上限）。"""

    def __init__(self) -> None:
        self.total = 0
        self.items: list[dict] = []

    def add(self, code: str, message: str, **ctx: Any) -> None:
        self.total += 1
        if len(self.items) < MAX_FAILURES:
            self.items.append({"code": code, "message": message, **ctx})

    @property
    def ok(self) -> bool:
        return self.total == 0


def _failure_outcome(findings: _Findings) -> dict:
    return {
        "valid": False,
        "failure_count": findings.total,
        "failures": findings.items,
    }


# ---- 记录条目的结构模式（类型级校验；业务取值由引用关系核对覆盖） ----

_FIELD_CHECKS = {
    "str": lambda v: isinstance(v, str),
    "int": _is_int,
    "nnint": lambda v: _is_int(v) and v >= 0,
    "posint": lambda v: _is_int(v) and v >= 1,
    "sha256": _is_sha256,
    "str_or_null": lambda v: v is None or isinstance(v, str),
    "bool": lambda v: isinstance(v, bool),
    "list": lambda v: isinstance(v, list),
}
_FIELD_DESCR = {
    "str": "a string",
    "int": "an integer",
    "nnint": "a non-negative integer",
    "posint": "a positive integer",
    "sha256": "a 64-character lowercase hex SHA-256 digest",
    "str_or_null": "a string or null",
    "bool": "a boolean",
    "list": "a list",
}

_DOC_SCHEMA = {
    "doc_id": "str", "filename": "str", "media_type": "str",
    "width": "posint", "height": "posint", "original_sha256": "sha256",
    "original_file": "str", "annotation_revision": "nnint", "created_at": "str",
}
_ANN_DOC_SCHEMA = {
    "doc_id": "str", "current_revision": "nnint",
    "revision_count": "posint", "revisions": "list",
}
_REVISION_SCHEMA = {"revision": "nnint", "rect_count": "nnint", "rects": "list"}
_RECT_SCHEMA = {"x": "int", "y": "int", "w": "int", "h": "int", "reason": "str"}
_PUB_SCHEMA = {
    "doc_id": "str", "version": "posint", "annotation_revision": "nnint",
    "original_sha256": "sha256", "output_sha256": "sha256",
    "output_file": "str", "created_at": "str",
    "batch_id": "str_or_null", "publish_at": "str_or_null",
    "withdrawn": "bool", "withdrawn_at": "str_or_null",
    "withdrawal_reason": "str_or_null",
}
_BATCH_SCHEMA = {
    "batch_id": "str", "created_at": "str",
    "publish_at": "str_or_null", "documents": "list",
}
_BATCH_MEMBER_SCHEMA = {"position": "nnint", "doc_id": "str", "version": "posint"}
_WITHDRAWAL_SCHEMA = {
    "doc_id": "str", "version": "posint", "reason": "str", "withdrawn_at": "str",
}


def _schema_problems(entry: Any, schema: dict) -> list[str]:
    if not isinstance(entry, dict):
        return ["entry must be a JSON object"]
    problems = []
    for key, kind in schema.items():
        if key not in entry:
            problems.append(f"missing field '{key}'")
        elif not _FIELD_CHECKS[kind](entry[key]):
            problems.append(f"field '{key}' must be {_FIELD_DESCR[kind]}")
    return problems


class _Verifier:
    """单份归档的核验器：按阶段核对并累计可定位的失败原因。"""

    def __init__(self, zf: zipfile.ZipFile, findings: _Findings) -> None:
        self.zf = zf
        self.findings = findings
        # name -> (kind, doc_id, version)，只含符合规定相对路径的成员
        self.kinds: dict[str, tuple[str, str | None, int | None]] = {}
        self.member_paths: set[str] = set()  # 规定的非清单成员
        self._digests: dict[str, str | None] = {}
        # manifest 解析结果（不可用时对应属性为 None）
        self.manifest: dict | None = None
        self.manifest_files: list | None = None
        self.manifest_entries: list[dict] = []  # 路径合法且未重复的清单条目
        self.manifest_record_counts: dict | None = None
        self.manifest_file_count: int | None = None
        # 五类记录解析结果（文件不可用时为 None）
        self.record_items: dict[str, list] = {}
        self.doc_entries: list[dict] | None = None
        self.ann_entries: list[dict] | None = None
        self.pub_entries: list[dict] | None = None
        self.batch_entries: list[dict] | None = None
        self.wd_entries: list[dict] | None = None
        self.derived_counts: dict[str, int] = {}

    # ---- 成员读取 ----

    def read_member(self, name: str) -> bytes | None:
        try:
            return self.zf.read(name)
        except _MEMBER_READ_ERRORS as exc:
            self.findings.add(
                "member_unreadable",
                f"ZIP member '{name}' cannot be read: {exc}",
                path=name,
            )
            return None

    def digest(self, name: str) -> str | None:
        """成员实际字节的 SHA-256（流式读取并缓存）；读不出来返回 None。"""
        if name not in self._digests:
            try:
                h = hashlib.sha256()
                with self.zf.open(name) as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                self._digests[name] = h.hexdigest()
            except _MEMBER_READ_ERRORS as exc:
                self.findings.add(
                    "member_unreadable",
                    f"ZIP member '{name}' cannot be read: {exc}",
                    path=name,
                )
                self._digests[name] = None
        return self._digests[name]

    # ---- 阶段一：成员名唯一且均为规定的相对路径 ----

    def check_members(self, infos: list[zipfile.ZipInfo]) -> None:
        names = [i.filename for i in infos]
        for name, occurrences in Counter(names).items():
            if occurrences > 1:
                self.findings.add(
                    "duplicate_member",
                    f"ZIP member '{name}' appears {occurrences} times;"
                    " member names must be unique",
                    path=name,
                    occurrences=occurrences,
                )
        for name in dict.fromkeys(names):
            cls = _classify(name)
            if cls is None:
                self.findings.add(
                    "unexpected_member",
                    f"ZIP member '{name}' is not one of the prescribed"
                    " relative paths (the five records JSON files,"
                    " manifest.json, originals/<doc_id>.png|jpg,"
                    " publications/<doc_id>/v<n>.png)",
                    path=name,
                )
            else:
                self.kinds[name] = cls
        self.member_paths = {
            n for n, c in self.kinds.items() if c[0] != "manifest"
        }

    # ---- 阶段二：manifest.json 可解析且结构完整 ----

    def check_manifest(self) -> None:
        if MANIFEST_NAME not in self.kinds:
            self.findings.add(
                "manifest_missing",
                "manifest.json is missing from the archive",
            )
            return
        raw = self.read_member(MANIFEST_NAME)
        if raw is None:
            return
        try:
            manifest = json.loads(raw)
        except ValueError as exc:
            self.findings.add(
                "manifest_invalid",
                f"manifest.json is not valid JSON: {exc}",
                path=MANIFEST_NAME,
            )
            return
        if not isinstance(manifest, dict):
            self.findings.add(
                "manifest_invalid",
                "manifest.json must be a JSON object",
                path=MANIFEST_NAME,
            )
            return
        self.manifest = manifest
        files = manifest.get("files")
        if not isinstance(files, list) or any(
            not isinstance(e, dict) for e in files
        ):
            self.findings.add(
                "manifest_invalid",
                "manifest.json 'files' must be a list of objects",
                path=MANIFEST_NAME,
            )
        else:
            self.manifest_files = files
        counts = manifest.get("record_counts")
        if not isinstance(counts, dict) or any(
            not _is_int(counts.get(k)) for k in RECORD_COUNT_KEYS
        ):
            self.findings.add(
                "manifest_invalid",
                "manifest.json 'record_counts' must be an object with integer"
                " counts for " + "/".join(RECORD_COUNT_KEYS),
                path=MANIFEST_NAME,
            )
        else:
            self.manifest_record_counts = counts
        file_count = manifest.get("file_count")
        if not _is_int(file_count):
            self.findings.add(
                "manifest_invalid",
                "manifest.json 'file_count' must be an integer",
                path=MANIFEST_NAME,
            )
        else:
            self.manifest_file_count = file_count
        if not isinstance(manifest.get("generated_at"), str) or not manifest[
            "generated_at"
        ]:
            self.findings.add(
                "manifest_invalid",
                "manifest.json 'generated_at' must be a non-empty string",
                path=MANIFEST_NAME,
            )

    # ---- 阶段三：清单条目合法、无重复，且与实际成员一一对应、摘要一致 ----

    def check_manifest_entries(self) -> None:
        if self.manifest_files is None:
            return
        seen: set[str] = set()
        for index, entry in enumerate(self.manifest_files):
            problems: list[str] = []
            path = entry.get("path")
            cls = _classify(path) if isinstance(path, str) else None
            if not isinstance(path, str) or not path:
                problems.append("'path' must be a non-empty string")
            elif cls is None:
                problems.append(
                    f"'path' {path!r} is not one of the prescribed relative"
                    " paths"
                )
            elif cls[0] == "manifest":
                problems.append("manifest.json itself must not be listed")
            kind = entry.get("kind")
            if kind not in ("original", "publication", "records"):
                problems.append(
                    "'kind' must be one of original/publication/records,"
                    f" got {kind!r}"
                )
            elif cls is not None and cls[0] not in ("manifest", kind):
                problems.append(
                    f"'kind' {kind!r} does not match path {path!r}"
                    f" (expected {cls[0]!r})"
                )
            if not _is_sha256(entry.get("sha256")):
                problems.append(
                    "'sha256' must be a 64-character lowercase hex digest"
                )
            fc = entry.get("file_count")
            if not _is_int(fc) or fc != 1:
                problems.append("'file_count' must be 1")
            if cls is not None and cls[0] == "original":
                if entry.get("doc_id") != cls[1]:
                    problems.append(
                        f"'doc_id' {entry.get('doc_id')!r} does not match"
                        f" path {path!r}"
                    )
                if "version" in entry:
                    problems.append("original entries must not carry 'version'")
            elif cls is not None and cls[0] == "publication":
                if entry.get("doc_id") != cls[1] or entry.get("version") != cls[2]:
                    problems.append(
                        f"'doc_id'/'version' do not match path {path!r}"
                    )
            elif cls is not None and cls[0] == "records":
                if "doc_id" in entry or "version" in entry:
                    problems.append(
                        "records entries must not carry 'doc_id'/'version'"
                    )
            if problems:
                self.findings.add(
                    "invalid_manifest_entry",
                    "; ".join(problems),
                    path=path if isinstance(path, str) else None,
                    entry_index=index,
                )
            if cls is not None and cls[0] != "manifest":
                if path in seen:
                    self.findings.add(
                        "duplicate_manifest_entry",
                        f"manifest lists '{path}' more than once",
                        path=path,
                    )
                else:
                    seen.add(path)
                    self.manifest_entries.append(entry)

    def check_manifest_against_members(self) -> None:
        if self.manifest_files is None:
            return
        entry_paths = {e["path"] for e in self.manifest_entries}
        for path in sorted(entry_paths - self.member_paths):
            self.findings.add(
                "member_missing",
                f"manifest lists '{path}' but the archive has no such member",
                path=path,
            )
        for name in sorted(self.member_paths - entry_paths):
            self.findings.add(
                "manifest_entry_missing",
                f"archive member '{name}' is not listed in the manifest",
                path=name,
            )
        for entry in self.manifest_entries:
            path = entry["path"]
            expected = entry.get("sha256")
            if path not in self.member_paths or not _is_sha256(expected):
                continue
            actual = self.digest(path)
            if actual is not None and actual != expected:
                self.findings.add(
                    "sha256_mismatch",
                    f"SHA-256 of '{path}' does not match the manifest",
                    path=path,
                    expected=expected,
                    actual=actual,
                )
        if self.manifest_file_count is not None and (
            self.manifest_file_count != len(self.member_paths)
        ):
            self.findings.add(
                "file_count_mismatch",
                f"manifest declares file_count {self.manifest_file_count} but"
                f" the archive holds {len(self.member_paths)} files"
                " (manifest.json excluded)",
                declared=self.manifest_file_count,
                actual=len(self.member_paths),
            )

    # ---- 阶段四：五类记录文件可解析、结构完整、内部计数自洽 ----

    def check_records(self) -> None:
        payloads: dict[str, Any] = {}
        for name in RECORD_NAMES:
            if name not in self.kinds:
                self.findings.add(
                    "records_missing",
                    f"required records file '{name}' is missing from the"
                    " archive",
                    path=name,
                )
                continue
            raw = self.read_member(name)
            if raw is None:
                continue
            try:
                payloads[name] = json.loads(raw)
            except ValueError as exc:
                self.findings.add(
                    "records_invalid",
                    f"'{name}' is not valid JSON: {exc}",
                    path=name,
                )
        self.doc_entries = self._record_list(
            payloads, "documents.json", "documents", _DOC_SCHEMA
        )
        self.ann_entries = self._annotation_docs(payloads.get("annotations.json"))
        self.pub_entries = self._record_list(
            payloads, "publications.json", "publications", _PUB_SCHEMA
        )
        self.batch_entries = self._batches(payloads.get("publication-batches.json"))
        self.wd_entries = self._record_list(
            payloads, "withdrawals.json", "withdrawals", _WITHDRAWAL_SCHEMA
        )
        # 发布记录的撤回标记与撤回时间/原因的空值形态必须一致
        if self.pub_entries is not None:
            for p in self.pub_entries:
                if p["withdrawn"] != (p["withdrawn_at"] is not None) or p[
                    "withdrawn"
                ] != (p["withdrawal_reason"] is not None):
                    self.findings.add(
                        "records_invalid",
                        f"publications.json entry for document '{p['doc_id']}'"
                        f" version {p['version']} has 'withdrawn'"
                        " inconsistent with 'withdrawn_at'/'withdrawal_reason'",
                        path="publications.json",
                        doc_id=p["doc_id"],
                        version=p["version"],
                    )
        # 记录计数（随后与 manifest.record_counts 核对）：按实际列出的条目数
        items = self.record_items
        if "documents.json" in items:
            self.derived_counts["documents"] = len(items["documents.json"])
        if "annotations.json" in items:
            self.derived_counts["annotation_revisions"] = sum(
                len(d["revisions"])
                for d in items["annotations.json"]
                if isinstance(d, dict) and isinstance(d.get("revisions"), list)
            )
        if "publications.json" in items:
            self.derived_counts["publications"] = len(items["publications.json"])
        if "publication-batches.json" in items:
            self.derived_counts["publication_batches"] = len(
                items["publication-batches.json"]
            )
        if "withdrawals.json" in items:
            self.derived_counts["withdrawals"] = len(items["withdrawals.json"])

    def _check_declared_count(
        self, payload: dict, name: str, field: str, actual: int
    ) -> None:
        declared = payload.get(field)
        if not _is_int(declared):
            self.findings.add(
                "records_invalid",
                f"'{name}' field '{field}' must be an integer",
                path=name,
            )
        elif declared != actual:
            self.findings.add(
                "records_count_mismatch",
                f"'{name}' declares {field} {declared} but the actual"
                f" count is {actual}",
                path=name,
                field=field,
                declared=declared,
                actual=actual,
            )

    def _record_list(
        self, payloads: dict, name: str, key: str, schema: dict
    ) -> list[dict] | None:
        """解析"顶层 count + 条目列表"形态的记录文件，返回结构合法的条目。"""
        payload = payloads.get(name)
        if payload is None:
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
            self.findings.add(
                "records_invalid",
                f"'{name}' must be a JSON object with a '{key}' list",
                path=name,
            )
            return None
        items = payload[key]
        self.record_items[name] = items
        self._check_declared_count(payload, name, "count", len(items))
        valid = []
        for index, item in enumerate(items):
            problems = _schema_problems(item, schema)
            if problems:
                self.findings.add(
                    "records_invalid",
                    f"'{name}' entry #{index}: " + "; ".join(problems),
                    path=name,
                    entry_index=index,
                )
            else:
                valid.append(item)
        return valid

    def _annotation_docs(self, payload: Any) -> list[dict] | None:
        name = "annotations.json"
        if payload is None:
            return None
        if not isinstance(payload, dict) or not isinstance(
            payload.get("documents"), list
        ):
            self.findings.add(
                "records_invalid",
                f"'{name}' must be a JSON object with a 'documents' list",
                path=name,
            )
            return None
        items = payload["documents"]
        self.record_items[name] = items
        self._check_declared_count(payload, name, "document_count", len(items))
        valid: list[dict] = []
        revision_total = 0  # 实际列出的修订总数（含结构非法的修订条目）
        for index, item in enumerate(items):
            problems = _schema_problems(item, _ANN_DOC_SCHEMA)
            if problems:
                self.findings.add(
                    "records_invalid",
                    f"'{name}' entry #{index}: " + "; ".join(problems),
                    path=name,
                    entry_index=index,
                )
                continue
            revisions = item["revisions"]
            revision_total += len(revisions)
            if item["revision_count"] != len(revisions):
                self.findings.add(
                    "revision_count_mismatch",
                    f"annotations for document '{item['doc_id']}' declare"
                    f" revision_count {item['revision_count']} but list"
                    f" {len(revisions)} revisions",
                    doc_id=item["doc_id"],
                    declared=item["revision_count"],
                    actual=len(revisions),
                )
            valid_revisions = []
            for rev in revisions:
                problems = _schema_problems(rev, _REVISION_SCHEMA)
                if problems:
                    self.findings.add(
                        "records_invalid",
                        f"'{name}' document '{item['doc_id']}' revision"
                        " entry: " + "; ".join(problems),
                        path=name,
                        doc_id=item["doc_id"],
                    )
                    continue
                if rev["rect_count"] != len(rev["rects"]):
                    self.findings.add(
                        "rect_count_mismatch",
                        f"revision {rev['revision']} of document"
                        f" '{item['doc_id']}' declares rect_count"
                        f" {rev['rect_count']} but lists"
                        f" {len(rev['rects'])} rects",
                        doc_id=item["doc_id"],
                        revision=rev["revision"],
                        declared=rev["rect_count"],
                        actual=len(rev["rects"]),
                    )
                for rect in rev["rects"]:
                    problems = _schema_problems(rect, _RECT_SCHEMA)
                    if problems:
                        self.findings.add(
                            "records_invalid",
                            f"'{name}' document '{item['doc_id']}' revision"
                            f" {rev['revision']} rect: " + "; ".join(problems),
                            path=name,
                            doc_id=item["doc_id"],
                            revision=rev["revision"],
                        )
                        break  # 每个修订只报一次结构问题，避免刷屏
                valid_revisions.append(rev)
            valid.append(
                {
                    "doc_id": item["doc_id"],
                    "current_revision": item["current_revision"],
                    "revisions": valid_revisions,
                }
            )
        self._check_declared_count(
            payload, name, "revision_count", revision_total
        )
        return valid

    def _batches(self, payload: Any) -> list[dict] | None:
        name = "publication-batches.json"
        if payload is None:
            return None
        if not isinstance(payload, dict) or not isinstance(
            payload.get("batches"), list
        ):
            self.findings.add(
                "records_invalid",
                f"'{name}' must be a JSON object with a 'batches' list",
                path=name,
            )
            return None
        items = payload["batches"]
        self.record_items[name] = items
        self._check_declared_count(payload, name, "count", len(items))
        valid = []
        for index, item in enumerate(items):
            problems = _schema_problems(item, _BATCH_SCHEMA)
            if problems:
                self.findings.add(
                    "records_invalid",
                    f"'{name}' entry #{index}: " + "; ".join(problems),
                    path=name,
                    entry_index=index,
                )
                continue
            members = []
            for m_index, member in enumerate(item["documents"]):
                problems = _schema_problems(member, _BATCH_MEMBER_SCHEMA)
                if problems:
                    self.findings.add(
                        "records_invalid",
                        f"'{name}' batch '{item['batch_id']}' member"
                        f" #{m_index}: " + "; ".join(problems),
                        path=name,
                        batch_id=item["batch_id"],
                    )
                else:
                    members.append(member)
            valid.append({"batch_id": item["batch_id"], "members": members})
        return valid

    # ---- 阶段五：记录之间的引用关系 ----

    def check_relationships(self) -> None:
        doc_by_id = self._index_documents()
        pub_by_key = self._index_publications(doc_by_id)
        self._index_withdrawals(pub_by_key)
        self._check_annotation_links(doc_by_id)
        self._check_batch_links(pub_by_key)

    def _index_documents(self) -> dict[str, dict] | None:
        if self.doc_entries is None:
            return None
        doc_by_id: dict[str, dict] = {}
        for d in self.doc_entries:
            doc_id = d["doc_id"]
            if doc_id in doc_by_id:
                self.findings.add(
                    "duplicate_document",
                    f"documents.json lists document '{doc_id}' more than once",
                    doc_id=doc_id,
                )
            else:
                doc_by_id[doc_id] = d
        return doc_by_id

    def _index_publications(
        self, doc_by_id: dict[str, dict] | None
    ) -> dict[tuple[str, int], dict] | None:
        if self.pub_entries is None:
            return None
        pub_by_key: dict[tuple[str, int], dict] = {}
        for p in self.pub_entries:
            key = (p["doc_id"], p["version"])
            if key in pub_by_key:
                self.findings.add(
                    "duplicate_publication",
                    f"publications.json lists document '{p['doc_id']}'"
                    f" version {p['version']} more than once",
                    doc_id=p["doc_id"],
                    version=p["version"],
                )
            else:
                pub_by_key[key] = p
        if doc_by_id is not None:
            for p in pub_by_key.values():
                doc = doc_by_id.get(p["doc_id"])
                if doc is None:
                    self.findings.add(
                        "unknown_document_reference",
                        f"publications.json refers to unknown document"
                        f" '{p['doc_id']}'",
                        doc_id=p["doc_id"],
                        version=p["version"],
                        source="publications.json",
                    )
                    continue
                if p["annotation_revision"] > doc["annotation_revision"]:
                    self.findings.add(
                        "unknown_annotation_revision",
                        f"publication version {p['version']} of document"
                        f" '{p['doc_id']}' froze annotation revision"
                        f" {p['annotation_revision']} but the document only"
                        f" reaches revision {doc['annotation_revision']}",
                        doc_id=p["doc_id"],
                        version=p["version"],
                        annotation_revision=p["annotation_revision"],
                        current_revision=doc["annotation_revision"],
                    )
                if p["original_sha256"] != doc["original_sha256"]:
                    self.findings.add(
                        "publication_original_mismatch",
                        f"publication version {p['version']} of document"
                        f" '{p['doc_id']}' records an original SHA-256 that"
                        " differs from documents.json",
                        doc_id=p["doc_id"],
                        version=p["version"],
                        expected=doc["original_sha256"],
                        actual=p["original_sha256"],
                    )
        # 每文档的发布版本必须是从 1 开始的连续序列（版本号不复用、不跳号）
        versions_by_doc: dict[str, list[int]] = {}
        for p in pub_by_key.values():
            versions_by_doc.setdefault(p["doc_id"], []).append(p["version"])
        for doc_id, versions in versions_by_doc.items():
            missing = sorted(set(range(1, max(versions) + 1)) - set(versions))
            if missing:
                self.findings.add(
                    "publication_version_gap",
                    f"publication versions of document '{doc_id}' must be a"
                    f" continuous 1..{max(versions)} sequence",
                    doc_id=doc_id,
                    missing_versions=missing,
                )
        return pub_by_key

    def _index_withdrawals(
        self, pub_by_key: dict[tuple[str, int], dict] | None
    ) -> None:
        if self.wd_entries is None:
            return
        wd_by_key: dict[tuple[str, int], dict] = {}
        for w in self.wd_entries:
            key = (w["doc_id"], w["version"])
            if key in wd_by_key:
                self.findings.add(
                    "duplicate_withdrawal",
                    f"withdrawals.json lists document '{w['doc_id']}'"
                    f" version {w['version']} more than once",
                    doc_id=w["doc_id"],
                    version=w["version"],
                )
            else:
                wd_by_key[key] = w
        if pub_by_key is None:
            return
        for key in wd_by_key:
            if key not in pub_by_key:
                self.findings.add(
                    "unknown_publication_reference",
                    f"withdrawals.json refers to unknown publication"
                    f" '{key[0]}' version {key[1]}",
                    doc_id=key[0],
                    version=key[1],
                    source="withdrawals.json",
                )
        # 撤回记录与发布记录的撤回字段必须双向一致
        for key, p in pub_by_key.items():
            w = wd_by_key.get(key)
            if (w is not None) != p["withdrawn"]:
                self.findings.add(
                    "withdrawal_mismatch",
                    f"publications.json marks document '{key[0]}' version"
                    f" {key[1]} withdrawn={p['withdrawn']} but"
                    " withdrawals.json "
                    + (
                        "has no such record"
                        if w is None
                        else "has a withdrawal record"
                    ),
                    doc_id=key[0],
                    version=key[1],
                )
            elif w is not None and (
                p["withdrawn_at"] != w["withdrawn_at"]
                or p["withdrawal_reason"] != w["reason"]
            ):
                self.findings.add(
                    "withdrawal_mismatch",
                    f"withdrawal fields of document '{key[0]}' version"
                    f" {key[1]} differ between publications.json and"
                    " withdrawals.json",
                    doc_id=key[0],
                    version=key[1],
                )

    def _check_annotation_links(self, doc_by_id: dict[str, dict] | None) -> None:
        if self.ann_entries is None or doc_by_id is None:
            return
        ann_by_doc: dict[str, dict] = {}
        for a in self.ann_entries:
            doc_id = a["doc_id"]
            if doc_id in ann_by_doc:
                self.findings.add(
                    "duplicate_annotation_document",
                    f"annotations.json lists document '{doc_id}' more than"
                    " once",
                    doc_id=doc_id,
                )
            else:
                ann_by_doc[doc_id] = a
        for doc_id in doc_by_id:
            if doc_id not in ann_by_doc:
                self.findings.add(
                    "annotation_document_missing",
                    f"annotations.json has no entry for document '{doc_id}'",
                    doc_id=doc_id,
                )
        for doc_id, a in ann_by_doc.items():
            doc = doc_by_id.get(doc_id)
            if doc is None:
                self.findings.add(
                    "unknown_document_reference",
                    f"annotations.json refers to unknown document '{doc_id}'",
                    doc_id=doc_id,
                    source="annotations.json",
                )
                continue
            if a["current_revision"] != doc["annotation_revision"]:
                self.findings.add(
                    "annotation_revision_mismatch",
                    f"annotations.json current_revision"
                    f" {a['current_revision']} does not match documents.json"
                    f" annotation_revision {doc['annotation_revision']} for"
                    f" document '{doc_id}'",
                    doc_id=doc_id,
                    expected=doc["annotation_revision"],
                    actual=a["current_revision"],
                )
            # 每份文档的标注修订必须是从 0 开始的连续序列
            revisions = [r["revision"] for r in a["revisions"]]
            for revision, occurrences in Counter(revisions).items():
                if occurrences > 1:
                    self.findings.add(
                        "duplicate_annotation_revision",
                        f"annotations.json lists revision {revision} of"
                        f" document '{doc_id}' more than once",
                        doc_id=doc_id,
                        revision=revision,
                    )
            expected = set(range(a["current_revision"] + 1))
            actual = set(revisions)
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            if missing or extra:
                self.findings.add(
                    "annotation_revision_gap",
                    f"annotation revisions of document '{doc_id}' must be the"
                    f" continuous range 0..{a['current_revision']}",
                    doc_id=doc_id,
                    missing_revisions=missing,
                    unexpected_revisions=extra,
                )

    def _check_batch_links(
        self, pub_by_key: dict[tuple[str, int], dict] | None
    ) -> None:
        batch_by_id: dict[str, dict] = {}
        member_keys: dict[str, set] = {}
        if self.batch_entries is not None:
            for b in self.batch_entries:
                batch_id = b["batch_id"]
                if batch_id in batch_by_id:
                    self.findings.add(
                        "duplicate_batch",
                        f"publication-batches.json lists batch '{batch_id}'"
                        " more than once",
                        batch_id=batch_id,
                    )
                    continue
                batch_by_id[batch_id] = b
                members = b["members"]
                member_keys[batch_id] = {
                    (m["doc_id"], m["version"]) for m in members
                }
                # 批次成员顺序：position 必须是 0..N-1 的连续序列
                positions = [m["position"] for m in members]
                for position, occurrences in Counter(positions).items():
                    if occurrences > 1:
                        self.findings.add(
                            "duplicate_batch_position",
                            f"batch '{batch_id}' lists position {position}"
                            " more than once",
                            batch_id=batch_id,
                            position=position,
                        )
                expected = set(range(len(members)))
                actual = set(positions)
                missing = sorted(expected - actual)
                extra = sorted(actual - expected)
                if missing or extra:
                    self.findings.add(
                        "batch_position_gap",
                        f"member positions of batch '{batch_id}' must be the"
                        f" continuous range 0..{len(members) - 1}",
                        batch_id=batch_id,
                        missing_positions=missing,
                        unexpected_positions=extra,
                    )
                if pub_by_key is not None:
                    for m in members:
                        key = (m["doc_id"], m["version"])
                        pub = pub_by_key.get(key)
                        if pub is None:
                            self.findings.add(
                                "unknown_publication_reference",
                                f"batch '{batch_id}' member position"
                                f" {m['position']} refers to unknown"
                                f" publication '{m['doc_id']}' version"
                                f" {m['version']}",
                                batch_id=batch_id,
                                position=m["position"],
                                doc_id=m["doc_id"],
                                version=m["version"],
                            )
                        elif pub["batch_id"] != batch_id:
                            self.findings.add(
                                "batch_membership_mismatch",
                                f"batch '{batch_id}' lists publication"
                                f" '{m['doc_id']}' version {m['version']} but"
                                " publications.json records batch_id"
                                f" {pub['batch_id']!r}",
                                batch_id=batch_id,
                                doc_id=m["doc_id"],
                                version=m["version"],
                                publication_batch_id=pub["batch_id"],
                            )
        # 反向：发布记录声称属于某批次时，批次必须存在且列其为成员
        if pub_by_key is not None and self.batch_entries is not None:
            for p in pub_by_key.values():
                batch_id = p["batch_id"]
                if batch_id is None:
                    continue
                key = (p["doc_id"], p["version"])
                if batch_id not in batch_by_id:
                    self.findings.add(
                        "unknown_batch_reference",
                        f"publication '{p['doc_id']}' version {p['version']}"
                        f" refers to unknown batch '{batch_id}'",
                        batch_id=batch_id,
                        doc_id=p["doc_id"],
                        version=p["version"],
                    )
                elif key not in member_keys[batch_id]:
                    self.findings.add(
                        "batch_member_missing",
                        f"publication '{p['doc_id']}' version {p['version']}"
                        f" records batch_id '{batch_id}' but the batch does"
                        " not list it as a member",
                        batch_id=batch_id,
                        doc_id=p["doc_id"],
                        version=p["version"],
                    )

    # ---- 阶段六：记录引用的文件存在且摘要一致；文件均须被记录引用 ----

    def check_recorded_files(self) -> None:
        referenced: set[str] = set()
        if self.doc_entries is not None:
            for d in self._unique_documents():
                ext = _MEDIA_TYPE_EXT.get(d["media_type"])
                if ext is None:
                    self.findings.add(
                        "unsupported_media_type",
                        f"document '{d['doc_id']}' has an unsupported"
                        f" media_type {d['media_type']!r}",
                        doc_id=d["doc_id"],
                        media_type=d["media_type"],
                    )
                else:
                    canonical = f"originals/{d['doc_id']}{ext}"
                    self._check_recorded_file(
                        d["original_file"],
                        canonical,
                        d["original_sha256"],
                        kind="original",
                        mismatch_code="original_sha256_mismatch",
                        ident={"doc_id": d["doc_id"]},
                    )
                referenced.add(d["original_file"])
        if self.pub_entries is not None:
            for p in self._unique_publications():
                canonical = f"publications/{p['doc_id']}/v{p['version']}.png"
                self._check_recorded_file(
                    p["output_file"],
                    canonical,
                    p["output_sha256"],
                    kind="publication",
                    mismatch_code="artifact_sha256_mismatch",
                    ident={"doc_id": p["doc_id"], "version": p["version"]},
                )
                referenced.add(p["output_file"])
        # 反向：包内原图/成品必须被记录引用（否则是清单外的多余文件）
        for name, (kind, doc_id, version) in self.kinds.items():
            if kind == "original" and self.doc_entries is not None:
                if name not in referenced:
                    self.findings.add(
                        "unreferenced_file",
                        f"archive member '{name}' is not referenced by any"
                        " document in documents.json",
                        path=name,
                        doc_id=doc_id,
                    )
            elif kind == "publication" and self.pub_entries is not None:
                if name not in referenced:
                    self.findings.add(
                        "unreferenced_file",
                        f"archive member '{name}' is not referenced by any"
                        " publication in publications.json",
                        path=name,
                        doc_id=doc_id,
                        version=version,
                    )

    def _unique_documents(self) -> Any:
        seen: set[str] = set()
        for d in self.doc_entries:
            if d["doc_id"] not in seen:
                seen.add(d["doc_id"])
                yield d

    def _unique_publications(self) -> Any:
        seen: set[tuple[str, int]] = set()
        for p in self.pub_entries:
            key = (p["doc_id"], p["version"])
            if key not in seen:
                seen.add(key)
                yield p

    def _check_recorded_file(
        self,
        path: str,
        canonical: str,
        expected_sha: str,
        *,
        kind: str,
        mismatch_code: str,
        ident: dict,
    ) -> None:
        """核对一条记录引用的文件：路径形态、成员存在性、字节摘要。"""
        cls = _classify(path)
        if path != canonical or cls is None or cls[0] != kind:
            self.findings.add(
                "invalid_file_reference",
                f"recorded file '{path}' is not the prescribed {kind} path"
                f" '{canonical}'",
                path=path,
                expected=canonical,
                **ident,
            )
            return
        if path not in self.kinds:
            self.findings.add(
                "referenced_file_missing",
                f"file '{path}' referenced by the records is missing from"
                " the archive",
                path=path,
                **ident,
            )
            return
        actual = self.digest(path)
        if actual is not None and actual != expected_sha:
            self.findings.add(
                mismatch_code,
                f"SHA-256 of '{path}' does not match the digest recorded"
                " for it",
                path=path,
                expected=expected_sha,
                actual=actual,
                **ident,
            )

    # ---- 阶段七：manifest.record_counts 与记录实际计数一致 ----

    def check_manifest_record_counts(self) -> None:
        if self.manifest_record_counts is None:
            return
        for key in RECORD_COUNT_KEYS:
            actual = self.derived_counts.get(key)
            if actual is None:
                continue  # 对应记录文件不可用，已按 records_missing/invalid 记录
            declared = self.manifest_record_counts[key]
            if declared != actual:
                self.findings.add(
                    "record_count_mismatch",
                    f"manifest record_counts.{key} is {declared} but the"
                    f" records list {actual}",
                    kind=key,
                    declared=declared,
                    actual=actual,
                )

    def outcome(self) -> dict:
        if not self.findings.ok:
            return _failure_outcome(self.findings)
        return {
            "valid": True,
            "failure_count": 0,
            "failures": [],
            "record_counts": {
                k: self.derived_counts[k] for k in RECORD_COUNT_KEYS
            },
            "file_count": len(self.member_paths),
            "generated_at": self.manifest["generated_at"],
        }


def verify_service_data_archive(
    data: bytes, *, max_uncompressed_bytes: int
) -> dict:
    """核验服务数据归档 ZIP 的字节内容，返回核验结果字典。

    结果包含 ``valid``（整体结论）、``failure_count`` 与逐条可定位的
    ``failures``；全部通过时另含 ``record_counts``、``file_count`` 与
    ``generated_at``。全程纯内存、只读：不解压到任何目录，不访问服务的
    数据库与文件。
    """
    findings = _Findings()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        findings.add(
            "invalid_zip",
            f"uploaded file is not a readable ZIP archive: {exc}",
        )
        return _failure_outcome(findings)
    with zf:
        infos = zf.infolist()
        # 防御 ZIP 炸弹：按中央目录声明的解压后总大小先拦截，再逐成员读取
        declared_total = sum(max(i.file_size, 0) for i in infos)
        if declared_total > max_uncompressed_bytes:
            findings.add(
                "invalid_zip",
                f"declared uncompressed content is {declared_total} bytes,"
                f" exceeding the verification limit of"
                f" {max_uncompressed_bytes} bytes",
            )
            return _failure_outcome(findings)
        verifier = _Verifier(zf, findings)
        verifier.check_members(infos)
        verifier.check_manifest()
        verifier.check_manifest_entries()
        verifier.check_manifest_against_members()
        verifier.check_records()
        verifier.check_relationships()
        verifier.check_recorded_files()
        verifier.check_manifest_record_counts()
        return verifier.outcome()
