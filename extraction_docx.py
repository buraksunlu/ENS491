import os
import json
from docx import Document
from oletools.olevba import VBA_Parser

SCRIPT_KEYWORDS = [
    "python", "python.exe",
    "powershell", "powershell.exe",
    "cmd.exe", "cmd /c",
    "wscript", "cscript",
    "bash", "sh ",
    "rundll32", "regsvr32",
    "mshta", "curl ", "wget "
]


def extract_metadata_docx(path: str) -> dict:
    metadata = {}

    doc = Document(path)
    core = doc.core_properties

    metadata = {
        "title": core.title,
        "subject": core.subject,
        "author": core.author,
        "last_saved_by": core.last_modified_by,
        "create_time": str(core.created),
        "last_saved_time": str(core.modified),
        "revision_number": core.revision,
        "category": core.category,
        "comments": core.comments,
        "keywords": core.keywords,
        "language": core.language,
    }

    return metadata


def extract_vba_with_oletools(path: str) -> dict:
    result = {
        "has_macros": False,
        "macro_count": 0,
        "autoexec_count": 0,
        "suspicious_count": 0,
        "ioc_count": 0,
        "obfuscated_item_count": 0,
        "script_keywords_found": [],
        "analysis_items": [],
        "vba_modules": [],
    }

    try:
        vbaparser = VBA_Parser(path)
    except Exception as e:
        result["error"] = f"VBA_Parser error: {e}"
        return result

    try:
        if not vbaparser.detect_vba_macros():
            return result

        result["has_macros"] = True

        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
            if not vba_code:
                continue

            lower_code = vba_code.lower()
            module_script_keywords = sorted({
                kw for kw in SCRIPT_KEYWORDS
                if kw.lower() in lower_code
            })

            result["vba_modules"].append({
                "container_file": filename,
                "stream_path": stream_path,
                "vba_filename": vba_filename,
                "raw_code": vba_code,
                "script_keywords_in_module": module_script_keywords,
            })

            result["script_keywords_found"].extend(module_script_keywords)

        result["macro_count"] = len(result["vba_modules"])
        result["script_keywords_found"] = sorted(set(result["script_keywords_found"]))

        analysis = vbaparser.analyze_macros()
        for kw_type, keyword, desc in analysis:
            item = {
                "type": kw_type,
                "keyword": keyword,
                "description": desc,
            }
            result["analysis_items"].append(item)

            t = (kw_type or "").lower()

            if "autoexec" in t:
                result["autoexec_count"] += 1
            if "suspicious" in t:
                result["suspicious_count"] += 1
            if "ioc" in t:
                result["ioc_count"] += 1
            if any(x in t for x in [
                "hex string", "base64", "dridex",
                "obfuscated", "vba expression", "strreverse"
            ]):
                result["obfuscated_item_count"] += 1

    finally:
        vbaparser.close()

    return result


def extract_docx_with_oletools(path: str) -> dict:
    features = {
        "file_path": os.path.abspath(path),
        "file_type": "docx",
        "file_size": os.path.getsize(path),
        "metadata": {},
        "vba_info": {},
    }

    try:
        features["metadata"] = extract_metadata_docx(path)
    except Exception as e:
        features["metadata_error"] = str(e)

    features["vba_info"] = extract_vba_with_oletools(path)

    return features


if __name__ == "__main__":
    # Command line usage:
    #   python extract_docx_oletools.py sample.docx
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract metadata and VBA-related information from a .docx file using oletools"
    )
    parser.add_argument("file", help="Path to .docx file")
    args = parser.parse_args()

    data = extract_docx_with_oletools(args.file)
    print(json.dumps(data, indent=2, ensure_ascii=False))
