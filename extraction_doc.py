import os
import json
import re
import string
from datetime import datetime
from io import BytesIO

from olefile import OleFileIO
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools import rtfobj


# ================== CONFIG ==================
# CHANGE THIS TO YOUR OWN DATASET PATH
DATASET_ROOT = "/home/burak/Desktop/dataset_root"  # EXAMPLE
DOC_ROOT = os.path.join(DATASET_ROOT, "doc")

OUTPUT_ROOT = os.path.join(DATASET_ROOT, "doc_extraction_results")
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
    Roughly detect if the file is:
      - classic OLE2 DOC  -> 'ole_doc'
      - RTF               -> 'rtf'
      - anything else     -> 'other'
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception:
        return "other"

    # RTF header: "{\rtf"
    if header.startswith(b"{\\rtf"):
        return "rtf"

    # OLE2 magic: D0 CF 11 E0 A1 B1 1A E1
    if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        return "ole_doc"

    return "other"


# ---------- BASIC FILE INFO ----------

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


# ---------- OLE METADATA ----------

def extract_ole_metadata(file_path: str) -> dict:
    """
    Extract OLE metadata from a DOC file:
    author, title, subject, revision, dates, etc.
    """
    meta_dict = {}
    try:
        ole = OleFileIO(file_path)
    except Exception as e:
        meta_dict["error"] = f"ole_open_error: {e}"
        return meta_dict

    try:
        meta = ole.get_metadata()
        meta_dict = {
            "author": meta.author,
            "last_saved_by": meta.last_saved_by,
            "title": meta.title,
            "subject": meta.subject,
            "comments": meta.comments,
            "template": meta.template,
            "revision_number": meta.revision_number,
            "create_time": str(meta.create_time) if meta.create_time else None,
            "last_saved_time": str(meta.last_saved_time)
            if meta.last_saved_time
            else None,
            "last_printed": str(meta.last_printed) if meta.last_printed else None,
            "num_pages": meta.num_pages,
            "num_words": meta.num_words,
            "num_chars": meta.num_chars,
            "application": meta.application,
        }
    except Exception as e:
        meta_dict = {"error": f"metadata_error: {e}"}
    finally:
        try:
            ole.close()
        except Exception:
            pass

    return meta_dict


# ---------- VBA / MACRO ANALYSIS (OLE DOC) ----------

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
        "macro_module_names": [],
    }


def _analyze_vba_code(full_code: str, module_names: list[str]) -> tuple[dict, dict]:
    """
    Shared logic to compute all our VBA-based features
    from a big concatenated VBA string.
    """
    summary = _empty_vba_summary()
    strings_part = _empty_vba_strings()
    strings_part["all_vba_code"] = full_code
    strings_part["macro_module_names"] = module_names

    # Keyword scanning
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

    # Code size / obfuscation structure
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

    return summary, strings_part


def extract_vba_from_doc(file_path: str) -> tuple[dict, dict]:
    """
    Extract macro/VBA analysis from a classic OLE DOC file.
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
            # No macros detected in this DOC
            return base_summary, base_strings

        base_summary["has_macros"] = True

        all_code_chunks = []
        module_names = []

        # Collect all macro streams
        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

        # Preserve macro_count and has_macros from this context
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


def extract_vba_from_ole_bytes(data: bytes, source_name: str) -> tuple[dict, dict]:
    """
    Same analysis as extract_vba_from_doc, but for an OLE object
    provided as raw bytes (for example, from an RTF embedded object).
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

        all_code_chunks = []
        module_names = []

        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                module_names.append(vba_filename)
                base_summary["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        summary, strings_part = _analyze_vba_code(full_code, module_names)

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


# ---------- RTF ANALYSIS (EMBEDDED OBJECTS) ----------

def extract_rtf_features(file_path: str) -> dict:
    """
    Use oletools.rtfobj to extract embedded objects from an RTF file.
    For each object, we collect:
      - size and index
      - whether it looks like OLE2, PE executable, ZIP, etc.
      - URLs / IP-like patterns in the decoded data
      - (if OLE2) nested VBA macro analysis via VBA_Parser(data=...)
    """
    info: dict = {
        "rtf_object_count": 0,
        "embedded_ole_object_count": 0,
        "embedded_ole_with_macros_count": 0,
        "embedded_pe_like_count": 0,
        "embedded_zip_like_count": 0,
        "objects": [],
    }

    try:
        for index, orig_len, data in rtfobj.rtf_iter_objects(file_path):
            info["rtf_object_count"] += 1
            obj_entry = {
                "index": index,
                "orig_len": orig_len,
                "decoded_size": len(data),
            }

            # Magic checks
            is_ole = data.startswith(
                b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
            )
            is_pe = data.startswith(b"MZ")
            is_zip = data.startswith(b"PK\x03\x04")

            obj_entry["is_ole2"] = bool(is_ole)
            obj_entry["is_pe_executable_like"] = bool(is_pe)
            obj_entry["is_zip_like"] = bool(is_zip)

            if is_ole:
                info["embedded_ole_object_count"] += 1

            if is_pe:
                info["embedded_pe_like_count"] += 1

            if is_zip:
                info["embedded_zip_like_count"] += 1

            # Extract text for URL/IP scanning
            try:
                text_sample = data.decode("latin-1", errors="ignore")
            except Exception:
                text_sample = ""

            urls = re.findall(
                r"https?://[^\s\"']+", text_sample, flags=re.IGNORECASE
            )
            if urls:
                obj_entry["urls"] = urls

            ip_like = re.findall(
                r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text_sample, flags=re.IGNORECASE
            )
            if ip_like:
                obj_entry["ip_like_list"] = ip_like

            # If it looks like an OLE object, run VBA analysis on it
            if is_ole:
                vba_summary, vba_strings = extract_vba_from_ole_bytes(
                    data, source_name=f"rtf_object_{index}"
                )
                obj_entry["vba_summary"] = vba_summary
                obj_entry["vba_strings"] = vba_strings

                if vba_summary.get("has_macros"):
                    info["embedded_ole_with_macros_count"] += 1

            info["objects"].append(obj_entry)

    except Exception as e:
        info["error"] = f"rtfobj_error: {e}"

    return info


# ---------- PROCESS SINGLE DOC/RTF ----------

def process_single_doc(file_path: str) -> dict:
    """
    Run the full pipeline for a single file stored under doc/:
    - detect real format (classic OLE DOC vs RTF)
    - basic file info
    - OLE metadata (for OLE DOC)
    - macro/VBA analysis (for OLE DOC)
    - RTF embedded objects + nested VBA (for RTF)
    - pack everything into a structured JSON and write to disk
    """
    label = get_label_from_path(file_path)
    file_info = get_file_basic_info(file_path)
    file_format = detect_file_format(file_path)

    errors = []
    ole_meta = {}
    vba_summary = _empty_vba_summary()
    vba_strings = _empty_vba_strings()
    rtf_features = {}

    if file_format == "ole_doc":
        # Classic Word 97-2003 DOC
        ole_meta = extract_ole_metadata(file_path)
        vba_summary, vba_strings = extract_vba_from_doc(file_path)
        if isinstance(ole_meta, dict) and "error" in ole_meta:
            errors.append(ole_meta["error"])
        if isinstance(vba_summary, dict) and "error" in vba_summary:
            errors.append(vba_summary["error"])

    elif file_format == "rtf":
        # RTF: no classic OLE metadata, but we analyse embedded objects
        ole_meta = {
            "note": "RTF file – classic OLE metadata is not applicable."
        }
        rtf_features = extract_rtf_features(file_path)
        if isinstance(rtf_features, dict) and "error" in rtf_features:
            errors.append(rtf_features["error"])

    else:
        # Unknown/other: try OLE anyway (might still be a valid OLE compound)
        ole_meta = extract_ole_metadata(file_path)
        vba_summary, vba_strings = extract_vba_from_doc(file_path)
        if isinstance(ole_meta, dict) and "error" in ole_meta:
            errors.append(ole_meta["error"])
        if isinstance(vba_summary, dict) and "error" in vba_summary:
            errors.append(vba_summary["error"])

    record = {
        "label": label,
        "file_info": file_info,
        "file_format": file_format,
        "ole_metadata": ole_meta,
        "vba_summary": vba_summary,
        "vba_strings": vba_strings,
        "rtf_objects": rtf_features,
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


# ---------- MAIN: SCAN ENTIRE DOC DATASET ----------

def iter_doc_files():
    """
    Yield .doc and .rtf files (exclude .docx) from:
        doc/malicious
        doc/benign
    under the dataset root.
    """
    for label_dir in ["malicious", "benign"]:
        base_dir = os.path.join(DOC_ROOT, label_dir)
        if not os.path.isdir(base_dir):
            print(f"[WARN] Folder not found: {base_dir}")
            continue

        for root, dirs, files in os.walk(base_dir):
            for fname in files:
                name_lower = fname.lower()
                if name_lower.endswith(".docx"):
                    continue  # handled by separate DOCX extractor
                if name_lower.endswith(".doc") or name_lower.endswith(".rtf"):
                    yield os.path.join(root, fname)


def main():
    print(f"[*] DOC/RTF extraction started at {datetime.now()}")
    count = 0
    for file_path in iter_doc_files():
        process_single_doc(file_path)
        count += 1

    print(f"[*] Finished at {datetime.now()}, total files processed: {count}")


if __name__ == "__main__":
    main()
