import os
import json
import re
import string
from datetime import datetime

from olefile import OleFileIO
from oletools.olevba import VBA_Parser, VBA_Scanner


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


# ---------- VBA / MACRO ANALYSIS ----------

def extract_vba_from_doc(file_path: str) -> tuple[dict, dict]:
    """
    Extract macro/VBA analysis from a DOC file.

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
    }

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        summary["error"] = f"VBA_Parser_error: {e}"
        return summary, strings_part

    try:
        if not vba.detect_vba_macros():
            # No macros detected in this DOC
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


# ---------- PROCESS SINGLE DOC ----------

def process_single_doc(file_path: str) -> dict:
    """
    Run the full pipeline for a single DOC file:
    - basic file info
    - OLE metadata
    - macro/VBA analysis
    - pack everything into a structured JSON and write to disk
    """
    label = get_label_from_path(file_path)

    file_info = get_file_basic_info(file_path)
    ole_meta = extract_ole_metadata(file_path)
    vba_summary, vba_strings = extract_vba_from_doc(file_path)

    errors = []
    if isinstance(ole_meta, dict) and "error" in ole_meta:
        errors.append(ole_meta["error"])
    if isinstance(vba_summary, dict) and "error" in vba_summary:
        errors.append(vba_summary["error"])

    record = {
        "label": label,
        "file_info": file_info,
        "ole_metadata": ole_meta,
        "vba_summary": vba_summary,
        "vba_strings": vba_strings,
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
    Yield only .doc files (exclude .docx) from:
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
                # Explicitly skip .docx
                if name_lower.endswith(".docx"):
                    continue
                if name_lower.endswith(".doc"):
                    yield os.path.join(root, fname)


def main():
    print(f"[*] DOC extraction started at {datetime.now()}")
    count = 0
    for file_path in iter_doc_files():
        process_single_doc(file_path)
        count += 1

    print(f"[*] Finished at {datetime.now()}, total DOC files processed: {count}")


if __name__ == "__main__":
    main()
