import os
import json
import re
import string
import zipfile
from datetime import datetime
from typing import Tuple, List, Dict

from oletools.olevba import VBA_Parser, VBA_Scanner


# ================== CONFIG ==================
# CHANGE THIS TO YOUR DATASET PATH
DATASET_ROOT = "/home/burak/Desktop/dataset"  
DOCX_ROOT = os.path.join(DATASET_ROOT, "docx")

OUTPUT_ROOT = os.path.join(DATASET_ROOT, "docx_extraction_results")
os.makedirs(OUTPUT_ROOT, exist_ok=True)
# ============================================


def make_json_safe(obj):
    """
    Recursively convert bytes/bytearray values inside dicts/lists
    into strings so that the whole object becomes JSON serializable.
    """
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8", errors="ignore")
        except Exception:
            return obj.hex()
    else:
        return obj


# ---------- FILE FORMAT DETECTION ----------

def detect_file_format(file_path: str) -> str:
    """
    Try to detect real container type:
      - ZIP-like (PK..)   -> 'zip_like' (OOXML / DOCX / DOCM)
      - classic OLE2 DOC  -> 'ole_doc'
      - RTF               -> 'rtf'
      - anything else     -> 'other'
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return "other"

    if header.startswith(b"{\\rtf"):
        return "rtf"

    if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole_doc"

    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06") or header.startswith(b"PK\x07\x08"):
        return "zip_like"

    return "other"


# ---------- BASIC FILE INFO & LABEL ----------

def get_file_basic_info(file_path: str) -> dict:
    st = os.stat(file_path)
    filename = os.path.basename(file_path)
    _, ext = os.path.splitext(filename)

    return {
        "file_path": file_path,
        "file_name": filename,
        "file_ext": ext.lower(),
        "file_size_bytes": st.st_size,
    }


def get_label_from_path(file_path: str) -> str:
    lower = file_path.lower()
    if os.sep + "malicious" + os.sep in lower:
        return "malicious"
    if os.sep + "benign" + os.sep in lower:
        return "benign"
    return "unknown"


# ---------- DOCX METADATA (core + app) ----------

def _get_text_by_suffix(root, suffix: str):
    """
    Helper: iterate over XML tree and return first element text
    whose tag ends with the given suffix (ignores namespaces).
    """
    for el in root.iter():
        if el.tag.endswith(suffix) and el.text is not None:
            return el.text
    return None


def extract_docx_metadata(file_path: str) -> dict:
    """
    Extract OOXML metadata from a DOCX/DOCM file:
    - creator, lastModifiedBy, created, modified
    - pages, words, characters, application (if present)
    """
    meta = {}
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            core_xml = None
            app_xml = None

            if "docProps/core.xml" in z.namelist():
                core_xml = z.read("docProps/core.xml")
            if "docProps/app.xml" in z.namelist():
                app_xml = z.read("docProps/app.xml")

            if core_xml:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(core_xml)
                meta["creator"] = _get_text_by_suffix(root, "creator")
                meta["last_modified_by"] = _get_text_by_suffix(root, "lastModifiedBy")
                meta["created"] = _get_text_by_suffix(root, "created")
                meta["modified"] = _get_text_by_suffix(root, "modified")
                meta["description"] = _get_text_by_suffix(root, "description")
                meta["subject"] = _get_text_by_suffix(root, "subject")
                meta["title"] = _get_text_by_suffix(root, "title")

            if app_xml:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(app_xml)
                pages = _get_text_by_suffix(root, "Pages")
                words = _get_text_by_suffix(root, "Words")
                chars = _get_text_by_suffix(root, "Characters")
                app_name = _get_text_by_suffix(root, "Application")

                meta["num_pages"] = int(pages) if pages and pages.isdigit() else None
                meta["num_words"] = int(words) if words and words.isdigit() else None
                meta["num_chars"] = int(chars) if chars and chars.isdigit() else None
                meta["application"] = app_name

    except Exception as e:
        meta = {"error": f"docx_metadata_error: {e}"}

    return meta


# ---------- VBA / MACRO ANALYSIS HELPERS ----------

SCRIPT_KEYWORDS = [
    "python", "python.exe",
    "powershell", "powershell.exe",
    "cmd.exe", "cmd /c",
    "wscript", "cscript",
    "bash", " sh ",
    "rundll32", "regsvr32",
    "mshta",
]

def _empty_vba_summary() -> dict:
    return {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keyword_count": 0,
        "autoexec_keyword_count": 0,
        "vba_length_chars": 0,
        "vba_line_count": 0,
        "vba_digit_ratio": 0.0,
        "vba_non_printable_ratio": 0.0,
        "url_count": 0,
        "ip_like_count": 0,
        "shell_indicator_total_hits": 0,
        "script_keyword_total_hits": 0,
        "obfuscated_item_count": 0,
    }


def _empty_vba_strings() -> dict:
    return {
        "all_vba_code": "",
        "urls": [],
        "ip_like_list": [],
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],
        "string_literals": [],
        "shell_indicator_hits": {},
        "script_keyword_hits": {},
        "macro_module_names": [],
        "vba_obfuscation_items": [],
    }


def _analyze_vba_code(full_code: str, module_names: List[str]) -> Tuple[dict, dict]:
    summary = _empty_vba_summary()
    strings_part = _empty_vba_strings()
    strings_part["all_vba_code"] = full_code
    strings_part["macro_module_names"] = module_names

    # Suspicious / AutoExec via VBA_Scanner
    scanner = VBA_Scanner(full_code)
    suspicious_keywords = []
    autoexec_keywords = []

    for kw_type, keyword, description, pattern in scanner.scan():
        if kw_type == "Suspicious":
            suspicious_keywords.append(f"{keyword} - {description}")
        elif kw_type == "AutoExec":
            autoexec_keywords.append(f"{keyword} - {description}")

    summary["suspicious_keyword_count"] = len(suspicious_keywords)
    summary["autoexec_keyword_count"] = len(autoexec_keywords)
    strings_part["suspicious_keywords_list"] = suspicious_keywords
    strings_part["autoexec_keywords_list"] = autoexec_keywords

    # Code size / structure
    code_len = len(full_code)
    summary["vba_length_chars"] = code_len
    summary["vba_line_count"] = full_code.count("\n") + 1 if code_len > 0 else 0

    digit_count = sum(ch.isdigit() for ch in full_code)
    non_printable_count = sum(ch not in string.printable for ch in full_code)

    summary["vba_digit_ratio"] = (digit_count / code_len) if code_len else 0.0
    summary["vba_non_printable_ratio"] = (
        non_printable_count / code_len if code_len else 0.0
    )

    # URLs & IP-like patterns
    urls = re.findall(r"https?://[^\s\"']+", full_code, flags=re.IGNORECASE)
    strings_part["urls"] = urls
    summary["url_count"] = len(urls)

    ip_like = re.findall(
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        full_code,
        flags=re.IGNORECASE,
    )
    strings_part["ip_like_list"] = ip_like
    summary["ip_like_count"] = len(ip_like)

    # String literals
    string_literals = re.findall(r'"([^"\r\n]{3,})"', full_code)
    strings_part["string_literals"] = string_literals

    # Shell indicators
    shell_indicators = [
        "Shell",
        "WScript.Shell",
        "CreateObject",
        "cmd.exe",
        "powershell",
        "WinHttp.WinHttpRequest",
        "XMLHTTP",
        "Msxml2.XMLHTTP",
        "ADODB.Stream",
        "WScript.CreateObject",
        "WScript.Echo",
    ]
    hits = {s: full_code.lower().count(s.lower()) for s in shell_indicators}
    strings_part["shell_indicator_hits"] = hits
    summary["shell_indicator_total_hits"] = sum(hits.values())

    # Script keywords (python, powershell, cmd, etc.) with lines
    script_hits: Dict[str, List[str]] = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in full_code.splitlines():
        lower_line = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in lower_line:
                script_hits[kw].append(line.strip())

    script_hits = {k: v for k, v in script_hits.items() if v}
    strings_part["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    return summary, strings_part


# ---------- VBA / MACRO ANALYSIS (DOCX / ANY) ----------

def extract_vba_from_docx(file_path: str) -> Tuple[dict, dict]:
    """
    Use oletools VBA_Parser on the file path directly.
    Works for OOXML DOCX/DOCM and many OLE / mixed cases.
    """
    base_summary = _empty_vba_summary()
    base_strings = _empty_vba_strings()

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        base_summary["error"] = f"VBA_Parser_error: {e}"
        return base_summary, base_strings

    try:
        if not vba.detect_vba_macros():
            return base_summary, base_strings

        base_summary["has_macros"] = True

        all_code_chunks: List[str] = []
        module_names: List[str] = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        # Obfuscation / encoded strings via analyze_macros()
        obf_items = []
        obf_count = 0
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                item = {
                    "type": kw_type,
                    "keyword": keyword,
                    "description": description,
                }
                obf_items.append(item)
                t = (kw_type or "").lower()
                if any(x in t for x in ["hex string", "base64", "dridex", "obfus"]):
                    obf_count += 1
        except Exception as e:
            obf_items.append(
                {
                    "type": "error",
                    "keyword": "",
                    "description": f"analyze_macros_error: {e}",
                }
            )

        strings_part["vba_obfuscation_items"] = obf_items
        summary["obfuscated_item_count"] = obf_count

        summary["has_macros"] = True
        summary["macro_count"] = base_summary["macro_count"]

        return summary, strings_part

    except Exception as e:
        base_summary["error"] = f"VBA_analysis_error: {e}"
        return base_summary, base_strings
    finally:
        try:
            vba.close()
        except Exception:
            pass


def extract_vba_from_ole_bytes(data: bytes, source_name: str) -> Tuple[dict, dict]:
    """
    For embedded OLE objects stored as .bin inside DOCX,
    run the same VBA analysis on raw bytes.
    """
    base_summary = _empty_vba_summary()
    base_strings = _empty_vba_strings()

    try:
        vba = VBA_Parser(filename=source_name, data=data)
    except Exception as e:
        base_summary["error"] = f"VBA_Parser_error: {e}"
        return base_summary, base_strings

    try:
        if not vba.detect_vba_macros():
            return base_summary, base_strings

        base_summary["has_macros"] = True

        all_code_chunks: List[str] = []
        module_names: List[str] = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        obf_items = []
        obf_count = 0
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                item = {
                    "type": kw_type,
                    "keyword": keyword,
                    "description": description,
                }
                obf_items.append(item)
                t = (kw_type or "").lower()
                if any(x in t for x in ["hex string", "base64", "dridex", "obfus"]):
                    obf_count += 1
        except Exception as e:
            obf_items.append(
                {
                    "type": "error",
                    "keyword": "",
                    "description": f"analyze_macros_error: {e}",
                }
            )

        strings_part["vba_obfuscation_items"] = obf_items
        summary["obfuscated_item_count"] = obf_count

        summary["has_macros"] = True
        summary["macro_count"] = base_summary["macro_count"]

        return summary, strings_part

    except Exception as e:
        base_summary["error"] = f"VBA_analysis_error: {e}"
        return base_summary, base_strings
    finally:
        try:
            vba.close()
        except Exception:
            pass


# ---------- DOCX PACKAGE-LEVEL FEATURES ----------

def extract_docx_package_features(file_path: str) -> Tuple[dict, dict]:
    """
    Analyze the OOXML package structure of the DOCX/DOCM file:
      - presence of vbaProject.bin (macro-enabled)
      - embedded OLE/ActiveX .bin objects (with nested VBA analysis)
      - number of XML/RELS/media/bin parts
      - external URLs from relationships/XML
      - suspicious keywords in XML/RELS text
    """
    summary = {
        "zip_entry_count": 0,
        "xml_file_count": 0,
        "rels_file_count": 0,
        "media_file_count": 0,
        "bin_file_count": 0,
        "has_vba_project_bin": False,
        "embedded_object_count": 0,
        "embedded_ole_object_count": 0,
        "embedded_ole_with_macros_count": 0,
        "embedded_pe_like_count": 0,
        "embedded_zip_like_count": 0,
        "embedded_rtf_like_count": 0,
        "external_url_count": 0,
        "suspicious_xml_keyword_total_hits": 0,
    }

    strings_part = {
        "external_urls": [],
        "suspicious_xml_keyword_hits": {},
        "embedded_objects": [],
    }

    suspicious_keywords = [
        "javascript:",
        "mhtml:",
        "shell",
        "wscript.shell",
        "createobject",
        "powershell",
        "cmd.exe",
        "document_open",
        "autoopen",
        "hyperlink",
        "includepicture",
        "external",
        "targetmode=\"external\"",
    ]

    suspicious_counts = {k: 0 for k in suspicious_keywords}
    external_url_set = set()

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            namelist = z.namelist()
            summary["zip_entry_count"] = len(namelist)

            for name in namelist:
                lower = name.lower()

                # Structural counters
                if lower.endswith(".rels"):
                    summary["rels_file_count"] += 1
                elif lower.endswith(".xml"):
                    summary["xml_file_count"] += 1

                if "/media/" in lower:
                    summary["media_file_count"] += 1
                if lower.endswith(".bin"):
                    summary["bin_file_count"] += 1

                if "vba" in lower and "vbaproject.bin" in lower:
                    summary["has_vba_project_bin"] = True

                is_embedded = (
                    "embeddings/" in lower
                    or "activex" in lower
                    or "oleobject" in lower
                    or "objectpool" in lower
                )

                # Textual parts for URL/keyword scanning
                if lower.endswith((".xml", ".rels", ".vml")):
                    try:
                        data = z.read(name)
                        text = data.decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""

                    text_lower = text.lower()

                    urls = re.findall(
                        r"https?://[^\s\"']+",
                        text,
                        flags=re.IGNORECASE,
                    )
                    for u in urls:
                        external_url_set.add(u)

                    for kw in suspicious_keywords:
                        count = text_lower.count(kw)
                        if count > 0:
                            suspicious_counts[kw] += count

                # Binary embedded objects
                if lower.endswith(".bin") and is_embedded:
                    summary["embedded_object_count"] += 1
                    try:
                        data = z.read(name)
                    except Exception:
                        continue

                    header = data[:16]
                    is_ole = header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
                    is_pe = header.startswith(b"MZ")
                    is_zip = header.startswith(b"PK\x03\x04")
                    is_rtf = header.startswith(b"{\\rtf")

                    obj_entry = {
                        "name": name,
                        "size": len(data),
                        "is_ole2": bool(is_ole),
                        "is_pe_executable_like": bool(is_pe),
                        "is_zip_like": bool(is_zip),
                        "is_rtf_like": bool(is_rtf),
                    }

                    if is_ole:
                        summary["embedded_ole_object_count"] += 1
                    if is_pe:
                        summary["embedded_pe_like_count"] += 1
                    if is_zip:
                        summary["embedded_zip_like_count"] += 1
                    if is_rtf:
                        summary["embedded_rtf_like_count"] += 1

                    try:
                        text_sample = data.decode("latin-1", errors="ignore")
                    except Exception:
                        text_sample = ""

                    urls_bin = re.findall(
                        r"https?://[^\s\"']+",
                        text_sample,
                        flags=re.IGNORECASE,
                    )
                    if urls_bin:
                        obj_entry["urls"] = urls_bin

                    ip_like_bin = re.findall(
                        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                        text_sample,
                        flags=re.IGNORECASE,
                    )
                    if ip_like_bin:
                        obj_entry["ip_like_list"] = ip_like_bin

                    if is_ole:
                        vba_summary, vba_strings = extract_vba_from_ole_bytes(
                            data, source_name=name
                        )
                        obj_entry["vba_summary"] = vba_summary
                        obj_entry["vba_strings"] = vba_strings
                        if vba_summary.get("has_macros"):
                            summary["embedded_ole_with_macros_count"] += 1

                    strings_part["embedded_objects"].append(obj_entry)

        strings_part["external_urls"] = sorted(external_url_set)
        summary["external_url_count"] = len(external_url_set)

        actual_hits = {k: v for k, v in suspicious_counts.items() if v > 0}
        strings_part["suspicious_xml_keyword_hits"] = actual_hits
        summary["suspicious_xml_keyword_total_hits"] = sum(actual_hits.values())

    except Exception as e:
        summary["error"] = f"docx_package_error: {e}"

    return summary, strings_part


# ---------- RAW TEXT FEATURES (ANY FILE) ----------

def extract_raw_text_features(file_path: str) -> Tuple[dict, dict]:
    """
    Independent of OOXML/VBA, scan the whole file as text to
    catch embedded scripts / encoded strings.
    """
    summary = {
        "raw_size_bytes": 0,
        "url_count": 0,
        "ip_like_count": 0,
        "script_keyword_total_hits": 0,
        "base64_candidate_count": 0,
        "hex_candidate_count": 0,
    }
    strings = {
        "urls": [],
        "ip_like_list": [],
        "script_keyword_hits": {},
        "base64_candidates": [],
        "hex_candidates": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        summary["error"] = f"raw_read_error: {e}"
        return summary, strings

    summary["raw_size_bytes"] = len(data)

    text = data.decode("latin-1", errors="ignore")

    urls = re.findall(r"https?://[^\s\"']+", text, flags=re.IGNORECASE)
    ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text, flags=re.IGNORECASE)

    strings["urls"] = urls
    strings["ip_like_list"] = ips
    summary["url_count"] = len(urls)
    summary["ip_like_count"] = len(ips)

    script_hits = {kw: [] for kw in SCRIPT_KEYWORDS}
    for line in text.splitlines():
        lower_line = line.lower()
        for kw in SCRIPT_KEYWORDS:
            if kw in lower_line:
                script_hits[kw].append(line.strip())
    script_hits = {k: v for k, v in script_hits.items() if v}
    strings["script_keyword_hits"] = script_hits
    summary["script_keyword_total_hits"] = sum(len(v) for v in script_hits.values())

    base64_candidates = re.findall(
        r"[A-Za-z0-9+/]{40,}={0,2}",
        text,
    )
    base64_candidates = list(dict.fromkeys(base64_candidates))
    strings["base64_candidates"] = base64_candidates
    summary["base64_candidate_count"] = len(base64_candidates)

    hex_candidates = re.findall(
        r"\b[0-9a-fA-F]{40,}\b",
        text,
    )
    hex_candidates = list(dict.fromkeys(hex_candidates))
    strings["hex_candidates"] = hex_candidates
    summary["hex_candidate_count"] = len(hex_candidates)

    return summary, strings


# ---------- PROCESS SINGLE DOCX ----------

def process_single_docx(file_path: str) -> dict:
    label = get_label_from_path(file_path)
    file_info = get_file_basic_info(file_path)
    file_format = detect_file_format(file_path)

    errors: List[str] = []

    raw_summary, raw_strings = extract_raw_text_features(file_path)
    if "error" in raw_summary:
        errors.append(raw_summary["error"])

    # VBA/macros (works for OOXML + many OLE cases)
    vba_summary, vba_strings = extract_vba_from_docx(file_path)
    if "error" in vba_summary:
        errors.append(vba_summary["error"])

    # Metadata + package features only if this is really ZIP/OOXML
    if file_format == "zip_like":
        docx_meta = extract_docx_metadata(file_path)
        pkg_summary, pkg_strings = extract_docx_package_features(file_path)
        if "error" in docx_meta:
            errors.append(docx_meta["error"])
        if "error" in pkg_summary:
            errors.append(pkg_summary["error"])
    elif file_format == "ole_doc":
        docx_meta = {
            "note": "OLE2 file stored under docx/. Classic DOC metadata is more appropriate."
        }
        pkg_summary = {
            "note": "Not a ZIP/OOXML container; package-level OOXML features not applicable."
        }
        pkg_strings = {}
    elif file_format == "rtf":
        docx_meta = {
            "note": "RTF file stored under docx/. DOCX metadata is not applicable."
        }
        pkg_summary = {
            "note": "RTF text file; no OOXML zip package to analyse."
        }
        pkg_strings = {}
    else:
        docx_meta = {
            "note": "Unknown container type; DOCX/OOXML metadata not available."
        }
        pkg_summary = {
            "note": "Unknown container type; package-level analysis skipped."
        }
        pkg_strings = {}

    record = {
        "label": label,
        "file_info": file_info,
        "file_format": file_format,
        "docx_metadata": docx_meta,
        "vba_summary": vba_summary,
        "vba_strings": vba_strings,
        "package_summary": pkg_summary,
        "package_strings": pkg_strings,
        "raw_text_summary": raw_summary,
        "raw_text_strings": raw_strings,
        "errors": errors,
    }

    safe_record = make_json_safe(record)
    base_name = os.path.basename(file_path)
    json_name = base_name + ".json"
    out_path = os.path.join(OUTPUT_ROOT, json_name)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(safe_record, f, ensure_ascii=False, indent=2)

    print(f"[OK] {file_path} -> {out_path}")
    return safe_record


# ---------- MAIN: SCAN ENTIRE DOCX DATASET ----------

def iter_docx_files():
    """
    Yield DOCX/DOCM (or whatever is placed there) from:
        docx/malicious
        docx/benign
    under the dataset root.
    """
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOCX_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue

        for root, _, files in os.walk(base_dir):
            for fname in files:
                lower = fname.lower()
                # We only care about files that are meant to be "docx-like"
                if lower.endswith(".docx") or lower.endswith(".docm"):
                    yield os.path.join(root, fname)


def main():
    print(f"[*] DOCX extraction started at {datetime.now()}")
    count = 0
    for file_path in iter_docx_files():
        process_single_docx(file_path)
        count += 1
    print(f"[*] Finished at {datetime.now()}, total DOCX files processed: {count}")


if __name__ == "__main__":
    main()
