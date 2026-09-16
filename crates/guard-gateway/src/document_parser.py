"""离线文档解析器；必须由受限容器调用，解析结果没有指令或批准权限。"""
import hashlib
import io
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat
import subprocess
import tempfile
import warnings
import zipfile


VERSION = "agentguard-document/1"
LIMITS = {
    "input_bytes": 8 * 1024 * 1024,
    "text_bytes": 32 * 1024,
    "metadata_bytes": 4096,
    "result_bytes": 128 * 1024,
    "pages": 100,
    "pdf_stream_bytes": 2 * 1024 * 1024,
    "pdf_total_stream_bytes": 16 * 1024 * 1024,
    "zip_entries": 256,
    "zip_member_bytes": 2 * 1024 * 1024,
    "zip_total_bytes": 20 * 1024 * 1024,
    "zip_ratio": 100,
    "xml_nodes": 100_000,
    "xml_depth": 64,
    "image_pixels": 4_000_000,
    "image_side": 8192,
    "image_frames": 1,
    "ocr_seconds": 15,
}
OCR_LANGUAGES = "eng+chi_sim+chi_tra"


class Rejected(Exception):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason


def require(condition, reason, status="limit_exceeded"):
    if not condition:
        raise Rejected(status, reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Result:
    def __init__(self):
        self.segments = []
        self.text_bytes = 0
        self.metadata = {}
        self.covered = []
        self.uncovered = []
        self.empty_units = []
        self.dependencies = {}

    def add(self, location, text):
        require(isinstance(text, str) and "\0" not in text, "正文不是支持的文本", "malformed")
        text = text.strip()
        if not text:
            self.empty_units.append(location)
            return
        self.text_bytes += len(text.encode("utf-8")) + (1 if self.segments else 0)
        require(self.text_bytes <= LIMITS["text_bytes"], "提取正文超限，不返回截断结果")
        self.segments.append({"location": location, "text": text})

    def meta(self, key, value):
        require(isinstance(value, (str, int, float, bool)), "元数据值类型不支持", "malformed")
        require(not isinstance(value, float) or math.isfinite(value), "元数据包含非有限数值", "malformed")
        self.metadata[key] = value
        require(len(json.dumps(self.metadata, ensure_ascii=False).encode()) <= LIMITS["metadata_bytes"],
                "元数据超限，不静默丢弃")


def xml(data):
    from defusedxml import ElementTree
    root = ElementTree.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    queue = [(root, 1)]
    count = 0
    while queue:
        node, depth = queue.pop()
        count += 1
        require(count <= LIMITS["xml_nodes"] and depth <= LIMITS["xml_depth"], "XML 节点或深度超限")
        queue.extend((child, depth + 1) for child in node)
    return root


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def texts(node):
    return "".join(child.text or "" for child in node.iter() if local_name(child.tag) == "t")


def office(data, kind, result):
    import defusedxml
    result.dependencies["defusedxml"] = defusedxml.__version__
    require(data.startswith(b"PK\x03\x04"), "Office 扩展名与 ZIP 文件头不符", "malformed")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        require(len(members) <= LIMITS["zip_entries"], "Office ZIP 条目过多")
        names = set()
        total = 0
        for item in members:
            name = item.filename
            require(name not in names, "Office 存在重复 ZIP 名称", "malformed")
            names.add(name)
            require(not name.startswith("/") and "\\" not in name and
                    not any(x in ("..", ".", "") for x in name.rstrip("/").split("/")),
                    "Office ZIP 路径非法", "malformed")
            require(not stat.S_ISLNK(item.external_attr >> 16), "Office ZIP 不允许链接", "malformed")
            require(not item.flag_bits & 1, "不支持加密 Office ZIP", "encrypted")
            require(item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "Office ZIP 压缩方式未支持", "unsupported")
            require(item.file_size <= LIMITS["zip_member_bytes"], "Office 单条目解压大小超限")
            total += item.file_size
            require(total <= LIMITS["zip_total_bytes"], "Office 总解压大小超限")
            require(item.file_size <= max(1, item.compress_size) * LIMITS["zip_ratio"], "Office 解压比例超限")
        require("[Content_Types].xml" in names, "缺少 Office 内容类型清单", "malformed")
        content_types = xml(archive.read("[Content_Types].xml"))
        types = [item.attrib.get("ContentType", "").lower() for item in content_types]
        require(not any("macroenabled" in t or "vbaproject" in t for t in types) and
                not any(n.lower().endswith("vbaproject.bin") for n in names),
                "不支持包含宏的 Office 文件", "unsupported")
        expected = {"docx": "wordprocessingml.document.main+xml",
                    "xlsx": "spreadsheetml.sheet.main+xml", "pptx": "presentationml.presentation.main+xml"}[kind]
        require(any(t == "application/vnd.openxmlformats-officedocument." + expected for t in types),
                "Office 主内容类型与所选格式不符", "malformed")
        for path in ["docProps/core.xml", "docProps/app.xml"]:
            if path in names:
                for node in xml(archive.read(path)).iter():
                    if node.text and node.text.strip():
                        result.meta(path + ":" + local_name(node.tag), node.text.strip())
        result.meta("zip_entries", len(members))
        result.meta("declared_uncompressed_bytes", total)
        result.covered = ["document_metadata", "office_text"]
        result.uncovered = ["图片及嵌入对象未解析", "不执行宏、脚本、公式或外部关系", "版面与渲染外观未验证"]
        if kind == "docx":
            require("word/document.xml" in names, "DOCX 缺少正文", "malformed")
            parts = ["word/document.xml"] + sorted(n for n in names if re.fullmatch(
                r"word/(header\d+|footer\d+|footnotes|endnotes|comments)\.xml", n))
            for part in parts:
                node = xml(archive.read(part))
                paragraphs = [texts(p) for p in node.iter() if local_name(p.tag) == "p"]
                result.add(part, "\n".join(paragraphs))
            result.uncovered.append("未列出的 Office 部件及修订语义未解释")
        elif kind == "xlsx":
            require("xl/workbook.xml" in names and "xl/_rels/workbook.xml.rels" in names,
                    "XLSX 缺少工作簿或关系", "malformed")
            shared = []
            if "xl/sharedStrings.xml" in names:
                shared = [texts(s) for s in xml(archive.read("xl/sharedStrings.xml"))
                          if local_name(s.tag) == "si"]
            relationships = {r.attrib.get("Id"): r.attrib for r in xml(archive.read("xl/_rels/workbook.xml.rels"))}
            sheets = [s for s in xml(archive.read("xl/workbook.xml")).iter() if local_name(s.tag) == "sheet"]
            require(len(sheets) <= LIMITS["pages"], "工作表数量超限")
            for index, sheet in enumerate(sheets, 1):
                rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
                relation = relationships.get(rel_id, {})
                require(relation.get("TargetMode") != "External", "外部工作表不能读取", "unsupported")
                target = relation.get("Target", "")
                part = target.lstrip("/") if target.startswith("/xl/") else "xl/" + target
                require(part in names and part.startswith("xl/worksheets/") and ".." not in PurePosixPath(part).parts,
                        "工作表关系目标未支持", "malformed")
                lines = []
                for cell in xml(archive.read(part)).iter():
                    if local_name(cell.tag) != "c":
                        continue
                    children = {local_name(c.tag): c for c in cell}
                    value = children.get("v")
                    text = value.text or "" if value is not None else ""
                    if "f" in children:
                        text = "公式（未计算）: " + (children["f"].text or "")
                    elif cell.attrib.get("t") == "s":
                        require(text.isdecimal() and int(text) < len(shared), "共享字符串索引无效", "malformed")
                        text = shared[int(text)]
                    elif cell.attrib.get("t") == "inlineStr":
                        text = texts(cell)
                    if text:
                        lines.append(cell.attrib.get("r", "未知单元格") + ": " + text)
                result.add(f"sheet:{index}:{sheet.attrib.get('name', '')}:{sheet.attrib.get('state', 'visible')}", "\n".join(lines))
            result.uncovered.append("公式未计算，缓存值不作为新计算结果；图表及格式未解析")
        else:
            require("ppt/presentation.xml" in names, "PPTX 缺少演示文稿", "malformed")
            slides = sorted(n for n in names if re.fullmatch(r"ppt/slides/slide\d+\.xml", n))
            require(len(slides) <= LIMITS["pages"], "幻灯片数量超限")
            for part in slides + sorted(n for n in names if re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", n)):
                result.add(part, "\n".join(texts(p) for p in xml(archive.read(part)).iter() if local_name(p.tag) == "p"))
            result.uncovered.append("按部件标识列出，不推断幻灯片显示顺序、隐藏状态或动画")


def pdf(data, result):
    import pypdf
    result.dependencies["pypdf"] = pypdf.__version__
    require(data.startswith(b"%PDF-"), "PDF 扩展名与文件头不符", "malformed")
    stream_limit = LIMITS["pdf_stream_bytes"]
    with pypdf.apply_configuration(
        maximum_declared_stream_length=LIMITS["input_bytes"],
        array_based_stream_maximum_output_length=stream_limit,
        zlib_maximum_output_length=stream_limit, lzw_maximum_output_length=stream_limit,
        run_length_maximum_output_length=stream_limit, image_maximum_buffer_size=stream_limit,
        zlib_maximum_recovery_input_length=stream_limit, jbig2dec_binary=None,
        page_tree_maximum_entries=1000, page_tree_maximum_depth=64,
        xform_maximum_invocations_per_extraction=100,
    ):
        try:
            reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
            require(not reader.is_encrypted, "不支持受密码保护 PDF", "encrypted")
            require(len(reader.pages) <= LIMITS["pages"], "PDF 页数超限")
            result.meta("pages", len(reader.pages))
            for key, value in (reader.metadata or {}).items():
                if isinstance(value, (str, int, float, bool)):
                    result.meta(str(key), value)
            result.covered = ["pdf_text_layer", "document_metadata"]
            result.uncovered = ["扫描图像未 OCR", "字体映射、阅读顺序及版面可能遗漏", "脚本、附件及表单动作不执行",
                                "仅解析标量元数据，XMP 及二进制元数据未覆盖"]
            decoded = 0
            for number, page in enumerate(reader.pages, 1):
                contents = page.get_contents()
                if contents is not None:
                    decoded += len(contents.get_data())
                    require(decoded <= LIMITS["pdf_total_stream_bytes"], "PDF 累计正文流解码大小超限")
                result.add(f"page:{number}", page.extract_text())
        except pypdf.errors.LimitReachedError:
            raise Rejected("limit_exceeded", "PDF 解码或对象结构超限") from None


def picture(data, kind, result):
    from PIL import Image, __version__
    result.dependencies["Pillow"] = __version__
    expected = "PNG" if kind == "png" else "JPEG"
    require(data.startswith(b"\x89PNG\r\n\x1a\n") if expected == "PNG" else data.startswith(b"\xff\xd8\xff"),
            "图片扩展名与文件头不符", "malformed")
    Image.MAX_IMAGE_PIXELS = LIMITS["image_pixels"]
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(io.BytesIO(data), formats=[expected])
        except (Image.DecompressionBombWarning, Image.DecompressionBombError):
            raise Rejected("limit_exceeded", "图片声明像素数量超限") from None
        width, height = image.size
        require(0 < width <= LIMITS["image_side"] and 0 < height <= LIMITS["image_side"] and
                width * height <= LIMITS["image_pixels"], "图片尺寸或像素数量超限")
        require(getattr(image, "n_frames", 1) == LIMITS["image_frames"], "不支持多帧图片", "unsupported")
        for key, value in image.info.items():
            if isinstance(value, (str, int, float, bool)):
                result.meta(str(key), value)
        for key, value in image.getexif().items():
            if isinstance(value, (str, int, float, bool)):
                result.meta(f"exif:{key}", value)
        result.meta("width", width)
        result.meta("height", height)
        image.load()
        with tempfile.TemporaryDirectory(prefix="agd-ocr-", dir="/tmp") as directory:
            # 重新编码成无附加元数据的位图，OCR 进程不再接触原始解析格式。
            raster = os.path.join(directory, "image.png")
            Image.frombytes("RGB", image.size, image.convert("RGB").tobytes()).save(raster)
            output = os.path.join(directory, "ocr")
            process = subprocess.run(["/usr/bin/tesseract", raster, output, "-l", OCR_LANGUAGES,
                                      "--psm", "6", "--oem", "1"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=LIMITS["ocr_seconds"], check=False,
                                     env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "OMP_THREAD_LIMIT": "1"})
            require(process.returncode == 0, "OCR 引擎未成功返回，不视为无文字", "parser_failed")
            with open(output + ".txt", "rb") as stream:
                text = stream.read(LIMITS["text_bytes"] + 1)
            require(len(text) <= LIMITS["text_bytes"], "OCR 正文超限")
            result.add("image:1:ocr", text.decode("utf-8"))
    result.covered = ["image_metadata", "image_ocr"]
    version = subprocess.run(["/usr/bin/tesseract", "--version"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=False,
                             env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
    require(version.returncode == 0 and len(version.stdout) <= 4096,
            "无法核对 OCR 引擎版本", "dependency_missing")
    result.dependencies["tesseract"] = version.stdout.decode("utf-8").splitlines()[0]
    result.dependencies["ocr_languages"] = OCR_LANGUAGES
    result.uncovered = ["OCR 可能误识别或漏字，不构成风险排除", "隐写、非文字像素、二进制元数据及嵌套 EXIF 未覆盖"]


def parse_bytes(data, kind):
    envelope = {"schema": "agentguard_document_v1", "parser_version": VERSION,
                "source_sha256": sha(data), "source_bytes": len(data), "format": kind,
                "instruction_authority": "none", "limits": LIMITS}
    try:
        require(len(data) <= LIMITS["input_bytes"], "原始文件大小超限")
        require(kind in ("pdf", "docx", "xlsx", "pptx", "png", "jpeg"), "文件格式未支持", "unsupported")
        result = Result()
        if kind == "pdf":
            pdf(data, result)
        elif kind in ("png", "jpeg"):
            picture(data, kind, result)
        else:
            office(data, kind, result)
        text = "\n".join(segment["text"] for segment in result.segments)
        status = "parsed" if result.segments and not result.empty_units else "partial"
        response = {**envelope, "status": status, "text": text, "text_sha256": sha(text.encode()),
                "segments": result.segments, "metadata": result.metadata,
                "coverage": {"parsed_layers": result.covered, "uncovered": result.uncovered,
                             "empty_units": result.empty_units}, "dependencies": result.dependencies}
        require(len(json.dumps(response, ensure_ascii=False).encode()) <= LIMITS["result_bytes"],
                "解析结果总大小超限，不返回截断结果")
        return response
    except Rejected as error:
        return {**envelope, "status": error.status, "reason": error.reason}
    except (ImportError, FileNotFoundError):
        return {**envelope, "status": "dependency_missing", "reason": "所需解析器、OCR 或语言数据不可用"}
    except subprocess.TimeoutExpired:
        return {**envelope, "status": "timeout", "reason": "OCR 超时，结果未知"}
    except MemoryError:
        return {**envelope, "status": "limit_exceeded", "reason": "解析内存超限"}
    except Exception:
        # 第三方错误可能包含原文或本机路径，不原样回传；失败不保留部分正文。
        return {**envelope, "status": "malformed", "reason": "解析失败，未取得完整可用结果"}


def main():
    # 仅供容器固定入口；格式由已批准的宿主请求决定，不接受文件中的命令。
    import sys
    require(len(sys.argv) == 2, "缺少唯一的文件格式", "unsupported")
    fd = os.open("/input/source", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), "输入必须为普通文件", "malformed")
        if metadata.st_size > LIMITS["input_bytes"]:
            print(json.dumps({"schema": "agentguard_document_v1", "parser_version": VERSION,
                "source_sha256": None, "source_bytes": metadata.st_size, "format": sys.argv[1],
                "status": "limit_exceeded", "reason": "原始文件大小超限，未读取或计算完整摘要",
                "instruction_authority": "none", "limits": LIMITS}, ensure_ascii=False))
            return
        data = stream.read(LIMITS["input_bytes"] + 1)
    print(json.dumps(parse_bytes(data, sys.argv[1]), ensure_ascii=False))


if __name__ == "__main__":
    main()
