"""服务数据归档接收方核验测试：上传归档 ZIP，整体判通过或逐条定位失败。

覆盖：
- 有效归档：含批次/撤回/定时发布/JPEG 原图的完整归档、空库归档均通过，
  返回各类记录计数与通过结论；
- 结构问题：非 ZIP、空上传、超大上传、成员重名、非法/穿越成员名、
  清单缺失或不可解析、记录文件缺失；
- 清单一致性：清单与实际成员不一一对应、逐文件 SHA-256 不符、
  file_count 与 record_counts 不符、清单条目字段非法/重复；
- 记录内部与引用关系：计数不自洽、标注修订不连续/与文档不符、发布版本
  不连续/重复、批次成员顺序断裂/成员关系不互认、撤回记录悬空或与发布
  记录不一致、未知文档/版本/批次引用；
- 文件与摘要：记录引用的文件缺失、原图/成品字节摘要与记录不符、
  文件未被记录引用、记录引用的路径不合规定；
- 核验全程只读：不在服务数据目录留下任何变化。
"""
import hashlib
import io
import json
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.test_api import jpeg_bytes, png_bytes, upload  # noqa: E402,F401


@pytest.fixture()
def client(tmp_path):
    settings = Settings(data_dir=str(tmp_path / "data"))
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


RECORD_NAMES = (
    "documents.json",
    "annotations.json",
    "publications.json",
    "publication-batches.json",
    "withdrawals.json",
)


def _new_doc(client, color=(10, 20, 30), filename="img.png", data=None):
    payload = data if data is not None else png_bytes(color=color)
    return upload(client, payload, filename).json()


def _annotate(client, doc_id, revision, rects):
    r = client.put(
        f"/documents/{doc_id}/annotations",
        json={"revision": revision, "rects": rects},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _publish(client, doc_id, **kwargs):
    r = client.post(f"/documents/{doc_id}/publish", json=kwargs or None)
    assert r.status_code == 201, r.text
    return r.json()


def _withdraw(client, doc_id, version, reason="遮盖遗漏：右下角工号未遮盖"):
    r = client.post(
        f"/documents/{doc_id}/publications/{version}/withdraw",
        json={"reason": reason},
    )
    assert r.status_code == 201, r.text
    return r


def _archive_bytes(client) -> bytes:
    r = client.post("/service-data-archives")
    assert r.status_code == 200, r.text
    return r.content


def _verify(client, data: bytes):
    return client.post(
        "/service-data-archive-verifications",
        files={"file": ("archive.zip", data, "application/zip")},
    )


def _failures(response) -> list[dict]:
    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "archive_verification_failed"
    # 未截断时逐条列出的条数等于失败总数
    assert detail["failure_count"] == len(detail["failures"])
    return detail["failures"]


def _codes(response) -> list[str]:
    return [f["code"] for f in _failures(response)]


# ---------------- 归档重建/篡改工具 ----------------

def _entries(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {i.filename: zf.read(i.filename) for i in zf.infolist()}


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in entries.items():
            zf.writestr(name, blob)
    return buf.getvalue()


def _edit_json(entries: dict[str, bytes], name: str, fn) -> None:
    payload = json.loads(entries[name])
    fn(payload)
    entries[name] = json.dumps(payload, ensure_ascii=False, indent=2).encode()


def _manifest_entry_for(name: str) -> dict:
    if name.startswith("originals/"):
        doc_id = name[len("originals/"):].rsplit(".", 1)[0]
        return {"path": name, "kind": "original", "doc_id": doc_id}
    if name.startswith("publications/"):
        doc_id, vfile = name[len("publications/"):].split("/")
        return {
            "path": name, "kind": "publication", "doc_id": doc_id,
            "version": int(vfile[1:-4]),
        }
    return {"path": name, "kind": "records"}


def _fix_records(entries: dict[str, bytes]) -> None:
    """重算五类记录 JSON 的内部计数字段（count/revision_count/rect_count）。"""
    docs = json.loads(entries["documents.json"])
    docs["count"] = len(docs["documents"])
    entries["documents.json"] = json.dumps(
        docs, ensure_ascii=False, indent=2).encode()
    anns = json.loads(entries["annotations.json"])
    anns["document_count"] = len(anns["documents"])
    anns["revision_count"] = 0
    for d in anns["documents"]:
        d["revision_count"] = len(d["revisions"])
        anns["revision_count"] += len(d["revisions"])
        for r in d["revisions"]:
            r["rect_count"] = len(r["rects"])
    entries["annotations.json"] = json.dumps(
        anns, ensure_ascii=False, indent=2).encode()
    pubs = json.loads(entries["publications.json"])
    pubs["count"] = len(pubs["publications"])
    entries["publications.json"] = json.dumps(
        pubs, ensure_ascii=False, indent=2).encode()
    batches = json.loads(entries["publication-batches.json"])
    batches["count"] = len(batches["batches"])
    entries["publication-batches.json"] = json.dumps(
        batches, ensure_ascii=False, indent=2).encode()
    wds = json.loads(entries["withdrawals.json"])
    wds["count"] = len(wds["withdrawals"])
    entries["withdrawals.json"] = json.dumps(
        wds, ensure_ascii=False, indent=2).encode()


def _fix_manifest(entries: dict[str, bytes]) -> None:
    """按当前成员重建清单：一一对应、逐文件 SHA-256、file_count、record_counts。"""
    manifest = json.loads(entries["manifest.json"])
    old = {e["path"]: e for e in manifest["files"]}
    files = []
    for name in sorted(n for n in entries if n != "manifest.json"):
        e = dict(old.get(name) or _manifest_entry_for(name))
        e["sha256"] = hashlib.sha256(entries[name]).hexdigest()
        e["file_count"] = 1
        files.append(e)
    manifest["files"] = files
    manifest["file_count"] = len(files)
    docs = json.loads(entries["documents.json"])
    anns = json.loads(entries["annotations.json"])
    pubs = json.loads(entries["publications.json"])
    batches = json.loads(entries["publication-batches.json"])
    wds = json.loads(entries["withdrawals.json"])
    manifest["record_counts"] = {
        "documents": len(docs["documents"]),
        "annotation_revisions": sum(
            len(d["revisions"]) for d in anns["documents"]),
        "publications": len(pubs["publications"]),
        "publication_batches": len(batches["batches"]),
        "withdrawals": len(wds["withdrawals"]),
    }
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()


def _consistent(entries: dict[str, bytes]) -> bytes:
    """篡改记录后修复内部计数与清单，使剩余问题只剩被测的关系/摘要错误。"""
    _fix_records(entries)
    _fix_manifest(entries)
    return _zip(entries)


# ---------------- 数据集 ----------------

def _rich_dataset(client):
    """三份文档：a 单份发布 v1 + 批次（a v2, b v1）+ b v1 撤回；c 为 JPEG
    原图 + 定时发布 v1（未到公开时间同样归档、同样核验）。"""
    a = _new_doc(client, (1, 2, 3))
    b = _new_doc(client, (4, 5, 6))
    c = _new_doc(client, data=jpeg_bytes(size=(10, 20), orientation=6),
                 filename="c.jpg")
    _annotate(client, a["doc_id"], 0, [
        {"x": 0, "y": 0, "w": 2, "h": 2, "reason": "甲"}])
    _annotate(client, b["doc_id"], 0, [
        {"x": 1, "y": 1, "w": 2, "h": 2, "reason": "乙"}])
    _publish(client, a["doc_id"])  # a v1
    r = client.post("/publication-batches", json={
        "documents": [
            {"doc_id": a["doc_id"], "expected_revision": 1},
            {"doc_id": b["doc_id"], "expected_revision": 1},
        ],
    })
    assert r.status_code == 201, r.text
    _withdraw(client, b["doc_id"], 1)
    _publish(client, c["doc_id"], publish_at="2026-10-20T08:00:00Z")  # c v1 定时
    return {"a": a, "b": b, "c": c, "batch_id": r.json()["batch_id"]}


# ---------------- 有效归档：通过并返回各类记录计数 ----------------

def test_valid_archive_passes_with_record_counts(client):
    _rich_dataset(client)
    archive = _archive_bytes(client)
    manifest = json.loads(_entries(archive)["manifest.json"])

    r = _verify(client, archive)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is True
    assert body["verdict"] == "pass"
    assert body["generated_at"] == manifest["generated_at"]
    assert body["record_counts"] == {
        "documents": 3,
        "annotation_revisions": 5,  # a、b 各 0/1 两个修订，c 仅 revision 0
        "publications": 4,          # a v1/v2、b v1、c v1（定时未到点也收录）
        "publication_batches": 1,
        "withdrawals": 1,
    }
    # 3 原图 + 4 成品 + 5 个记录 JSON（manifest.json 自身不计入）
    assert body["file_count"] == 12


def test_empty_database_archive_passes(client):
    r = _verify(client, _archive_bytes(client))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is True
    assert body["record_counts"] == {
        "documents": 0, "annotation_revisions": 0, "publications": 0,
        "publication_batches": 0, "withdrawals": 0,
    }
    assert body["file_count"] == 5  # 仅 5 个记录 JSON


# ---------------- 上传与 ZIP 结构 ----------------

def test_non_zip_upload_fails(client):
    failures = _failures(_verify(client, b"this is not a zip archive"))
    assert [f["code"] for f in failures] == ["invalid_zip"]


def test_empty_upload_rejected(client):
    r = _verify(client, b"")
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "empty_upload"


def test_oversized_upload_rejected(tmp_path):
    settings = Settings(data_dir=str(tmp_path / "data"), max_verify_bytes=16)
    app = create_app(settings)
    with TestClient(app) as c:
        r = _verify(c, b"x" * 32)
    assert r.status_code == 413
    assert r.json()["detail"]["code"] == "payload_too_large"


def test_duplicate_member_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, blob in entries.items():
            zf.writestr(name, blob)
        zf.writestr("documents.json", entries["documents.json"])  # 重名成员
    failures = _failures(_verify(client, buf.getvalue()))
    assert [f["code"] for f in failures] == ["duplicate_member"]
    assert failures[0]["path"] == "documents.json"
    assert failures[0]["occurrences"] == 2


def test_unexpected_member_names_fail(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    entries["notes.txt"] = b"hello"          # 多余文件
    entries["../escape.png"] = b"x"          # 目录穿越
    entries["/abs/path.png"] = b"x"          # 绝对路径
    entries["originals/"] = b""              # 目录条目
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["unexpected_member"] * 4
    assert {f["path"] for f in failures} == {
        "notes.txt", "../escape.png", "/abs/path.png", "originals/",
    }


def test_missing_manifest_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    del entries["manifest.json"]
    assert _codes(_verify(client, _zip(entries))) == ["manifest_missing"]


def test_unparseable_manifest_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    entries["manifest.json"] = b"{not json"
    assert _codes(_verify(client, _zip(entries))) == ["manifest_invalid"]


def test_missing_records_file_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    del entries["withdrawals.json"]  # 清单仍列出它，记录文件本身也缺失
    assert _codes(_verify(client, _zip(entries))) == [
        "member_missing",       # 清单列出 withdrawals.json 但成员不存在
        "file_count_mismatch",  # 清单声明 12 个文件，实际只剩 11 个成员
        "records_missing",      # 规定的记录文件缺失
    ]


# ---------------- 清单一致性 ----------------

def test_member_bytes_not_matching_manifest_fail(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    path = f"originals/{ids['a']['doc_id']}.png"
    entries[path] = b"tampered-original-bytes"  # 清单与记录都未更新
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == [
        "sha256_mismatch",          # 与清单不符
        "original_sha256_mismatch",  # 与 documents.json 记录不符
    ]
    sha_fail, rec_fail = failures
    assert sha_fail["path"] == path
    assert sha_fail["actual"] == hashlib.sha256(
        b"tampered-original-bytes").hexdigest()
    assert rec_fail["doc_id"] == ids["a"]["doc_id"]


def test_artifact_digest_not_matching_records_fail(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    path = f"publications/{ids['a']['doc_id']}/v1.png"
    entries[path] = b"tampered-artifact-bytes"
    _fix_manifest(entries)  # 清单同步篡改，但 publications.json 未改
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["artifact_sha256_mismatch"]
    f = failures[0]
    assert f["path"] == path
    assert f["doc_id"] == ids["a"]["doc_id"] and f["version"] == 1


def test_member_without_manifest_entry_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    removed = manifest["files"].pop(0)  # 删除一个清单条目，成员仍在包内
    # file_count 指成员总数（仍为 12），不随 files 列表条目减少而改
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["manifest_entry_missing"]
    assert failures[0]["path"] == removed["path"]


def test_manifest_entry_without_member_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    ghost = "originals/" + "f" * 32 + ".png"
    manifest["files"].append({
        "path": ghost, "kind": "original", "doc_id": "f" * 32,
        "sha256": "0" * 64, "file_count": 1,
    })
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["member_missing"]
    assert failures[0]["path"] == ghost


def test_file_count_mismatch_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    manifest["file_count"] = 999
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["file_count_mismatch"]
    assert failures[0]["declared"] == 999
    assert failures[0]["actual"] == 12


def test_record_count_mismatch_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    manifest["record_counts"]["documents"] = 99
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["record_count_mismatch"]
    f = failures[0]
    assert f["kind"] == "documents"
    assert f["declared"] == 99 and f["actual"] == 3


def test_invalid_manifest_entry_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    manifest["files"][0]["kind"] = "bogus"
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["invalid_manifest_entry"]
    assert failures[0]["path"] == manifest["files"][0]["path"]


def test_duplicate_manifest_entry_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    manifest = json.loads(entries["manifest.json"])
    manifest["files"].append(dict(manifest["files"][0]))
    entries["manifest.json"] = json.dumps(
        manifest, ensure_ascii=False, indent=2).encode()
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["duplicate_manifest_entry"]
    assert failures[0]["path"] == manifest["files"][0]["path"]


# ---------------- 记录内部计数 ----------------

def test_records_count_mismatch_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "documents.json", lambda p: p.update(count=99))
    _fix_manifest(entries)  # 清单摘要/record_counts 同步，只剩内部计数错误
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["records_count_mismatch"]
    f = failures[0]
    assert f["path"] == "documents.json" and f["field"] == "count"
    assert f["declared"] == 99 and f["actual"] == 3


def test_rect_count_mismatch_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        doc = next(d for d in payload["documents"]
                   if d["doc_id"] == ids["a"]["doc_id"])
        rev1 = next(r for r in doc["revisions"] if r["revision"] == 1)
        rev1["rect_count"] = 5  # 实际只有 1 个矩形

    _edit_json(entries, "annotations.json", edit)
    _fix_manifest(entries)
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["rect_count_mismatch"]
    f = failures[0]
    assert f["doc_id"] == ids["a"]["doc_id"] and f["revision"] == 1
    assert f["declared"] == 5 and f["actual"] == 1


# ---------------- 引用关系：文档 ↔ 连续标注修订 ----------------

def test_annotation_revision_gap_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        doc = next(d for d in payload["documents"]
                   if d["doc_id"] == ids["a"]["doc_id"])
        doc["revisions"] = [r for r in doc["revisions"] if r["revision"] != 1]

    _edit_json(entries, "annotations.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["annotation_revision_gap"]
    f = failures[0]
    assert f["doc_id"] == ids["a"]["doc_id"]
    assert f["missing_revisions"] == [1]


def test_annotation_revision_mismatch_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        doc = next(d for d in payload["documents"]
                   if d["doc_id"] == ids["a"]["doc_id"])
        doc["current_revision"] = 0  # documents.json 中 annotation_revision 为 1

    _edit_json(entries, "annotations.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == [
        "annotation_revision_mismatch",  # 与 documents.json 不一致
        "annotation_revision_gap",       # 修订 1 超出 0..0 范围
    ]
    assert failures[0]["expected"] == 1 and failures[0]["actual"] == 0
    assert failures[1]["unexpected_revisions"] == [1]


def test_duplicate_annotation_revision_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        doc = next(d for d in payload["documents"]
                   if d["doc_id"] == ids["a"]["doc_id"])
        doc["revisions"].append(dict(doc["revisions"][0]))  # 重复 revision 0

    _edit_json(entries, "annotations.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["duplicate_annotation_revision"]
    assert failures[0]["revision"] == 0


def test_annotation_document_missing_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "annotations.json", lambda p: p.update(
        documents=[d for d in p["documents"]
                   if d["doc_id"] != ids["b"]["doc_id"]]))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["annotation_document_missing"]
    assert failures[0]["doc_id"] == ids["b"]["doc_id"]


def test_annotations_referencing_unknown_document_fail(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    ghost = "g" * 32
    _edit_json(entries, "annotations.json", lambda p: p["documents"].append({
        "doc_id": ghost, "current_revision": 0, "revision_count": 1,
        "revisions": [{"revision": 0, "rect_count": 0, "rects": []}],
    }))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["unknown_document_reference"]
    f = failures[0]
    assert f["doc_id"] == ghost and f["source"] == "annotations.json"


# ---------------- 引用关系：发布版本 ----------------

def test_publication_version_gap_fails(client):
    d = _new_doc(client, (7, 7, 7))
    _annotate(client, d["doc_id"], 0, [
        {"x": 0, "y": 0, "w": 1, "h": 1, "reason": "r"}])
    _publish(client, d["doc_id"])  # v1
    _publish(client, d["doc_id"])  # v2
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        p = next(p for p in payload["publications"] if p["version"] == 2)
        p["version"] = 3  # 篡改版本号，制造 1..3 缺 2
        p["output_file"] = f"publications/{d['doc_id']}/v3.png"

    _edit_json(entries, "publications.json", edit)
    entries[f"publications/{d['doc_id']}/v3.png"] = entries.pop(
        f"publications/{d['doc_id']}/v2.png")
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["publication_version_gap"]
    f = failures[0]
    assert f["doc_id"] == d["doc_id"] and f["missing_versions"] == [2]


def test_duplicate_publication_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "publications.json", lambda p: p[
        "publications"].append(dict(p["publications"][0])))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["duplicate_publication"]
    f = failures[0]
    assert f["doc_id"] and f["version"] == 1


def test_publication_referencing_unknown_document_fail(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    ghost = "g" * 32
    ghost_bytes = b"ghost-artifact"
    ghost_sha = hashlib.sha256(ghost_bytes).hexdigest()

    def edit(payload):
        payload["publications"].append({
            "doc_id": ghost, "version": 1, "annotation_revision": 0,
            "original_sha256": "0" * 64, "output_sha256": ghost_sha,
            "output_file": f"publications/{ghost}/v1.png",
            "created_at": "2026-01-01T00:00:00+00:00",
            "batch_id": None, "publish_at": None,
            "withdrawn": False, "withdrawn_at": None,
            "withdrawal_reason": None,
        })

    _edit_json(entries, "publications.json", edit)
    entries[f"publications/{ghost}/v1.png"] = ghost_bytes  # 文件与摘要自洽
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["unknown_document_reference"]
    f = failures[0]
    assert f["doc_id"] == ghost and f["source"] == "publications.json"


def test_publication_original_mismatch_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "publications.json", lambda p: p[
        "publications"][0].update(original_sha256="0" * 64))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["publication_original_mismatch"]


def test_unknown_annotation_revision_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        p = next(p for p in payload["publications"]
                 if p["doc_id"] == ids["a"]["doc_id"] and p["version"] == 1)
        p["annotation_revision"] = 7  # 文档当前修订号只有 1

    _edit_json(entries, "publications.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["unknown_annotation_revision"]
    f = failures[0]
    assert f["annotation_revision"] == 7 and f["current_revision"] == 1


# ---------------- 引用关系：批次成员顺序与互认 ----------------

def test_batch_position_gap_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "publication-batches.json", lambda p: p[
        "batches"][0]["documents"][1].update(position=2))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["batch_position_gap"]
    f = failures[0]
    assert f["missing_positions"] == [1] and f["unexpected_positions"] == [2]


def test_batch_membership_mismatch_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        p = next(p for p in payload["publications"]
                 if p["doc_id"] == ids["a"]["doc_id"] and p["version"] == 2)
        p["batch_id"] = None  # 批次仍列其为成员，发布记录却无所属批次

    _edit_json(entries, "publications.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["batch_membership_mismatch"]
    f = failures[0]
    assert f["batch_id"] == ids["batch_id"]
    assert f["doc_id"] == ids["a"]["doc_id"] and f["version"] == 2


def test_unknown_batch_reference_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        p = next(p for p in payload["publications"]
                 if p["doc_id"] == ids["a"]["doc_id"] and p["version"] == 2)
        p["batch_id"] = "ghostbatch"

    _edit_json(entries, "publications.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == [
        "batch_membership_mismatch",  # 批次成员与发布记录互不认可
        "unknown_batch_reference",    # 发布记录指向不存在的批次
    ]
    assert failures[1]["batch_id"] == "ghostbatch"


def test_batch_member_missing_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "publication-batches.json", lambda p: p[
        "batches"][0].update(documents=[
            m for m in p["batches"][0]["documents"]
            if m["doc_id"] != ids["b"]["doc_id"]]))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["batch_member_missing"]
    f = failures[0]
    assert f["batch_id"] == ids["batch_id"]
    assert f["doc_id"] == ids["b"]["doc_id"] and f["version"] == 1


# ---------------- 引用关系：撤回记录 ----------------

def test_withdrawal_referencing_unknown_publication_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "withdrawals.json", lambda p: p[
        "withdrawals"].append({
            "doc_id": ids["b"]["doc_id"], "version": 99,
            "reason": "x", "withdrawn_at": "2026-01-01T00:00:00+00:00",
        }))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["unknown_publication_reference"]
    f = failures[0]
    assert f["doc_id"] == ids["b"]["doc_id"] and f["version"] == 99
    assert f["source"] == "withdrawals.json"


def test_withdrawal_mismatch_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))

    def edit(payload):
        p = next(p for p in payload["publications"]
                 if p["doc_id"] == ids["b"]["doc_id"] and p["version"] == 1)
        p.update(withdrawn=False, withdrawn_at=None, withdrawal_reason=None)

    _edit_json(entries, "publications.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["withdrawal_mismatch"]
    f = failures[0]
    assert f["doc_id"] == ids["b"]["doc_id"] and f["version"] == 1


def test_duplicate_withdrawal_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    _edit_json(entries, "withdrawals.json", lambda p: p[
        "withdrawals"].append(dict(p["withdrawals"][0])))
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == ["duplicate_withdrawal"]


# ---------------- 文件与摘要 ----------------

def test_referenced_file_missing_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    path = f"originals/{ids['a']['doc_id']}.png"
    del entries[path]  # 清单同步删除，但 documents.json 仍引用该文件
    _fix_manifest(entries)
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["referenced_file_missing"]
    f = failures[0]
    assert f["path"] == path and f["doc_id"] == ids["a"]["doc_id"]


def test_unreferenced_file_fails(client):
    _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    ghost = "originals/" + "e" * 32 + ".png"
    entries[ghost] = b"ghost-original"  # 清单同步登记，但记录未引用
    _fix_manifest(entries)
    failures = _failures(_verify(client, _zip(entries)))
    assert [f["code"] for f in failures] == ["unreferenced_file"]
    assert failures[0]["path"] == ghost


def test_invalid_file_reference_fails(client):
    ids = _rich_dataset(client)
    entries = _entries(_archive_bytes(client))
    wrong = "originals/" + "d" * 32 + ".png"

    def edit(payload):
        doc = next(d for d in payload["documents"]
                   if d["doc_id"] == ids["a"]["doc_id"])
        doc["original_file"] = wrong  # 规定的形态应是 originals/{doc_id}.png

    _edit_json(entries, "documents.json", edit)
    failures = _failures(_verify(client, _consistent(entries)))
    assert [f["code"] for f in failures] == [
        "invalid_file_reference",  # 记录的路径不符合规定形态
        "unreferenced_file",       # 真正的原图成员因此无人引用
    ]
    assert failures[0]["path"] == wrong
    assert failures[0]["expected"] == (
        f"originals/{ids['a']['doc_id']}.png")


# ---------------- 核验全程只读 ----------------

def _tree_digest(root: str) -> dict[str, str]:
    snap = {}
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            with open(p, "rb") as f:
                snap[os.path.relpath(p, root)] = hashlib.sha256(
                    f.read()).hexdigest()
    return snap


def test_verification_does_not_touch_service_data(client):
    _rich_dataset(client)
    archive = _archive_bytes(client)
    before = _tree_digest(client.app.state.settings.data_dir)

    assert _verify(client, archive).status_code == 200  # 有效归档
    entries = _entries(archive)
    entries["manifest.json"] = b"{}"  # 无效归档同样只读
    assert _verify(client, _zip(entries)).status_code == 422

    after = _tree_digest(client.app.state.settings.data_dir)
    assert before == after  # 数据目录（SQLite 库、原图、成品）零变化
