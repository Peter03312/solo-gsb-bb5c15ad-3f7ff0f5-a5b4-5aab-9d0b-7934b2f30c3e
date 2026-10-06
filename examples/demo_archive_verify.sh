#!/usr/bin/env bash
# 服务数据归档接收方核验端到端示例：
#   造数（上传/标注/批次发布/撤回）-> 生成服务数据归档 ZIP
#   -> 接收方核验（POST /service-data-archive-verifications，multipart 上传 ZIP）：
#      有效 -> 200 + 各类记录计数 + "verdict":"pass"
#   -> 篡改包内一份发布成品字节后再次核验：
#      -> 422 archive_verification_failed，failures 逐条给出可定位原因
# 核验全程在内存中进行：不解压到服务数据目录，不改写任何现有记录。
# 依赖：curl、python3（仅用于解析 JSON、生成示例图、篡改并重建 ZIP）
set -euo pipefail

BASE="${BASE:-http://localhost:8000}"

python3 - <<'EOF'
from PIL import Image
Image.new("RGB", (64, 48), (40, 100, 170)).save("/tmp/vfy_a.png")
Image.new("RGB", (64, 48), (170, 100, 40)).save("/tmp/vfy_b.png")
EOF

upload() {  # $1 = 文件路径 -> doc_id
  curl -sS -F "file=@$1" "$BASE/documents" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['doc_id'])"
}

echo "== 1. 上传两份原图，标注、批次发布并撤回其中一版（制造多种记录） =="
A=$(upload /tmp/vfy_a.png)
B=$(upload /tmp/vfy_b.png)
echo "A=$A B=$B"
curl -sS -X PUT "$BASE/documents/$A/annotations" -H 'Content-Type: application/json' \
  -d '{"revision":0,"rects":[{"x":4,"y":4,"w":12,"h":10,"reason":"身份证号"}]}' >/dev/null
curl -sS -X PUT "$BASE/documents/$B/annotations" -H 'Content-Type: application/json' \
  -d '{"revision":0,"rects":[{"x":40,"y":30,"w":10,"h":10,"reason":"人脸"}]}' >/dev/null
curl -sS -X POST "$BASE/publication-batches" -H 'Content-Type: application/json' \
  -d "{\"documents\":[
    {\"doc_id\":\"$A\",\"expected_revision\":1},
    {\"doc_id\":\"$B\",\"expected_revision\":1}
  ]}" >/dev/null
curl -sS -X POST "$BASE/documents/$B/publications/1/withdraw" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"遮盖遗漏：右下角工号未遮盖"}' >/dev/null

echo
echo "== 2. 生成服务数据归档 ZIP（运维导出，同一数据库快照） =="
curl -sS -o /tmp/vfy_archive.zip -X POST "$BASE/service-data-archives" \
  -w "HTTP %{http_code}, %{size_download} bytes\n"

echo
echo "== 3. 接收方核验：有效归档 -> 200 + 各类记录计数 + pass =="
curl -sS -o /tmp/vfy_ok.json -w "HTTP %{http_code}\n" \
  -F "file=@/tmp/vfy_archive.zip" "$BASE/service-data-archive-verifications"
python3 - <<'EOF'
import json
body = json.load(open("/tmp/vfy_ok.json"))
print(" valid        :", body["valid"])
print(" verdict      :", body["verdict"])
print(" generated_at :", body["generated_at"])
print(" record_counts:", json.dumps(body["record_counts"], ensure_ascii=False))
print(" file_count   :", body["file_count"], "（不含 manifest.json 自身）")
EOF

echo
echo "== 4. 篡改包内一份发布成品字节（清单与记录都不改）后再次核验 =="
python3 - <<'EOF'
import io, zipfile
src = zipfile.ZipFile("/tmp/vfy_archive.zip")
items = [(i.filename, src.read(i.filename)) for i in src.infolist()]
src.close()
target = next(n for n, _ in items if n.startswith("publications/"))
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
    for name, blob in items:
        if name == target:
            blob = b"tampered-artifact-bytes"  # 与清单和记录中的摘要都不再一致
        out.writestr(name, blob)
open("/tmp/vfy_archive_tampered.zip", "wb").write(buf.getvalue())
print("已篡改:", target)
EOF
curl -sS -o /tmp/vfy_bad.json -w "HTTP %{http_code}\n" \
  -F "file=@/tmp/vfy_archive_tampered.zip" "$BASE/service-data-archive-verifications"
python3 - <<'EOF'
import json
detail = json.load(open("/tmp/vfy_bad.json"))["detail"]
print(" code         :", detail["code"])
print(" failure_count:", detail["failure_count"])
for f in detail["failures"]:
    loc = f.get("path") or ""
    print(f"  - {f['code']}: {loc} :: {f['message'][:72]}")
EOF

echo
echo "== 5. 结论：有效归档给出各类记录计数与 pass；被篡改归档整体判失败，"
echo "   failures 逐条定位到具体文件/记录，可据此拒绝交接。"
