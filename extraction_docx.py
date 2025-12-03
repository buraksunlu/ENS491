import os
import json
import re
import string
import zipfile
from datetime import datetime
from typing import Tuple

from oletools.olevba import VBA_Parser, VBA_Scanner


# ================== CONFIG ==================
# CHANGE THIS TO YOUR OWN DATASET PATH
DATASET_ROOT = "/home/burak/Desktop/dataset_root"  # EXAMPLE
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


# ---------- BASIC FILE INFO & LABEL ----------

def get_file_basic_info(file_path: str) -> dict:
    """
    Basic filesystem-level information about the document.
    """
    st = os.stat(file_path)
    filename = os.path.basename(file_path)
    name, ext = os.path.splitext(filename)

    return {
        "file_path": file_path,
        "file_name": filename,
        "file_ext": ext.lower(),
        "file_size_bytes": st.st_size,
    }


def get_label_from_path(file_path: str) -> str:
    """
    Infer label (malicious/benign) from the folder name in the path.
    """
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
            # core.xml (creator, created, modified, etc.)
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
                meta["last_modified_by"] = _get_text_by_suffix(
                    root, "lastModifiedBy"
                )
                meta["created"] = _get_text_by_suffix(root, "created")
                meta["modified"] = _get_text_by_suffix(root, "modified")
                meta["description"] = _get_text_by_suffix(root, "description")
                meta["subject"] = _get_text_by_suffix(root, "subject")
                meta["title"] = _get_text_by_suffix(root, "title")

            if app_xml:
                import xml.etree.ElementTree as ET

                root = ET.fromstring(app_xml)
                # These may not exist for every file
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


# ---------- VBA / MACRO ANALYSIS (DOCX) ----------

def extract_vba_from_docx(file_path: str) -> Tuple[dict, dict]:
    """
    Extract macro/VBA analysis from a DOCX/DOCM file using oletools.

    Returns:
        vba_summary:
            - has_macros
            - macro_count
            - suspicious_keyword_count
            - autoexec_keyword_count
            - vba_length_chars
            - vba_line_count
            - vba_digit_ratio
            - vba_non_printable_ratio
            - url_count
            - ip_like_count
            - shell_indicator_total_hits

        vba_strings:
            - all_vba_code
            - urls
            - ip_like_list
            - suspicious_keywords_list
            - autoexec_keywords_list
            - string_literals
            - shell_indicator_hits
            - macro_module_names
    """
    summary = {
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
    }

    strings_part = {
        "all_vba_code": "",
        "urls": [],
        "ip_like_list": [],
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],
        "string_literals": [],
        "shell_indicator_hits": {},
        "macro_module_names": [],
    }

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        summary["error"] = f"VBA_Parser_error: {e}"
        return summary, strings_part

    try:
        if not vba.detect_vba_macros():
            # No macros detected
            return summary, strings_part

        summary["has_macros"] = True

        all_code_chunks = []
        module_names = []

        # Collect all macro streams
        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        strings_part["all_vba_code"] = full_code
        strings_part["macro_module_names"] = module_names

        # --- oletools keyword scanning ---
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

        # --- Extra features: obfuscation / structure / content ---

        code_len = len(full_code)
        summary["vba_length_chars"] = code_len
        summary["vba_line_count"] = (
            full_code.count("\n") + 1 if code_len > 0 else 0
        )

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
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b", full_code, flags=re.IGNORECASE
        )
        strings_part["ip_like_list"] = ip_like
        summary["ip_like_count"] = len(ip_like)

        # String literals (including obfuscated-looking strings)
        string_literals = re.findall(r'"([^"\r\n]{3,})"', full_code)
        strings_part["string_literals"] = string_literals

        # Shell / download / execution indicators
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

    except Exception as e:
        summary["error"] = f"VBA_analysis_error: {e}"
    finally:
        try:
            vba.close()
        except Exception:
            pass

    return summary, strings_part


# ---------- DOCX PACKAGE-LEVEL FEATURES ----------

def extract_docx_package_features(file_path: str) -> Tuple[dict, dict]:
    """
    Analyze the OOXML package structure of the DOCX/DOCM file:
    - presence of vbaProject.bin (macro-enabled)
    - embedded OLE objects and ActiveX
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
        "ole_object_count": 0,
        "activex_object_count": 0,
        "external_url_count": 0,
        "suspicious_xml_keyword_total_hits": 0,
    }

    strings_part = {
        "external_urls": [],
        "suspicious_xml_keyword_hits": {},
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

                # Count structural elements
                if lower.endswith(".rels"):
                    summary["rels_file_count"] += 1
                elif lower.endswith(".xml"):
                    summary["xml_file_count"] += 1

                if "/media/" in lower:
                    summary["media_file_count"] += 1
                if lower.endswith(".bin"):
                    summary["bin_file_count"] += 1
                if "vba" in lower and "vbaProject.bin".lower() in lower:
                    summary["has_vba_project_bin"] = True
                if "embeddings/" in lower:
                    summary["embedded_object_count"] += 1
                if "oleobject" in lower or "objectpool" in lower:
                    summary["ole_object_count"] += 1
                if "activex" in lower:
                    summary["activex_object_count"] += 1

                # Inspect only textual parts for URLs and suspicious keywords
                if lower.endswith((".xml", ".rels", ".vml")):
                    try:
                        data = z.read(name)
                        text = data.decode("utf-8", errors="ignore")
                    except Exception:
                        continue

                    text_lower = text.lower()

                    # URLs from XML/RELS
                    urls = re.findall(
                        r"https?://[^\s\"']+",
                        text,
                        flags=re.IGNORECASE,
                    )
                    for u in urls:
                        external_url_set.add(u)

                    # Suspicious keyword hits in XML text
                    for kw in suspicious_keywords:
                        count = text_lower.count(kw)
                        if count > 0:
                            suspicious_counts[kw] += count

        strings_part["external_urls"] = sorted(external_url_set)
        summary["external_url_count"] = len(external_url_set)

        # Filter keywords that actually appear
        actual_hits = {k: v for k, v in suspicious_counts.items() if v > 0}
        strings_part["suspicious_xml_keyword_hits"] = actual_hits
        summary["suspicious_xml_keyword_total_hits"] = sum(actual_hits.values())

    except Exception as e:
        summary["error"] = f"docx_package_error: {e}"

    return summary, strings_part


# ---------- PROCESS SINGLE DOCX ----------

def process_single_docx(file_path: str) -> dict:
    """
    Run the full pipeline for a single DOCX/DOCM file:
    - basic file info
    - DOCX metadata (core + app)
    - macro/VBA analysis
    - OOXML package-level analysis
    - pack everything into a structured JSON and write to disk
    """
    label = get_label_from_path(file_path)

    file_info = get_file_basic_info(file_path)
    docx_meta = extract_docx_metadata(file_path)
    vba_summary, vba_strings = extract_vba_from_docx(file_path)
    pkg_summary, pkg_strings = extract_docx_package_features(file_path)

    errors = []
    if isinstance(docx_meta, dict) and "error" in docx_meta:
        errors.append(docx_meta["error"])
    if isinstance(vba_summary, dict) and "error" in vba_summary:
        errors.append(vba_summary["error"])
    if isinstance(pkg_summary, dict) and "error" in pkg_summary:
        errors.append(pkg_summary["error"])

    record = {
        "label": label,
        "file_info": file_info,
        "docx_metadata": docx_meta,
        "vba_summary": vba_summary,
        "vba_strings": vba_strings,
        "package_summary": pkg_summary,
        "package_strings": pkg_strings,
        "errors": errors,
    }

    # Write per-file JSON
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
    Yield DOCX/DOCM files from:
        docx/malicious
        docx/benign
    under the dataset root.
    """
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOCX_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue

        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                lower = fname.lower()
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
