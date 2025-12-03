import os
import csv
import json
from datetime import datetime

from oletools.olevba import VBA_Parser, VBA_Scanner

# ==== CONFIG - BUNU KENDİ YOLUNA GÖRE DÜZENLE ====
DATA_ROOT = "/path/to/your_dataset_root"  # Örn: "/home/burak/docs_dataset"
OUTPUT_DIR = os.path.join(DATA_ROOT, "extraction_results")
# ===============================================

os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_file_basic_info(file_path: str) -> dict:
    """
    Basic file info: name, extension, size (bytes)
    """
    stat = os.stat(file_path)
    filename = os.path.basename(file_path)
    name, ext = os.path.splitext(filename)

    return {
        "file_path": file_path,
        "file_name": filename,
        "file_ext": ext.lower(),
        "file_size_bytes": stat.st_size,
    }


def extract_vba_features(file_path: str) -> dict:
    """
    Use oletools.olevba to:
    - detect macros
    - count macros
    - collect raw VBA code
    - count suspicious / autoexec keywords
    """
    result = {
        "has_macros": False,
        "macro_count": 0,
        "suspicious_keyword_count": 0,
        "autoexec_keyword_count": 0,
        "suspicious_keywords_list": [],
        "autoexec_keywords_list": [],
        "all_vba_code": "",  # concatenated
    }

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        result["error"] = f"VBA_Parser_error: {e}"
        return result

    try:
        if not vba.detect_vba_macros():
            # No macros
            return result

        result["has_macros"] = True

        all_code_chunks = []

        # Extract all macros
        for (subfilename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            if vba_code:
                all_code_chunks.append(vba_code)
                result["macro_count"] += 1

        full_code = "\n\n".join(all_code_chunks)
        result["all_vba_code"] = full_code

        # Scan for suspicious & autoexec keywords
        scanner = VBA_Scanner(full_code)
        suspicious_keywords = []
        autoexec_keywords = []

        for kw_type, keyword, description, pattern in scanner.scan():
            # kw_type: 'Suspicious', 'AutoExec', 'IOC', etc.
            if kw_type == 'Suspicious':
                suspicious_keywords.append(f"{keyword} - {description}")
            elif kw_type == 'AutoExec':
                autoexec_keywords.append(f"{keyword} - {description}")

        result["suspicious_keyword_count"] = len(suspicious_keywords)
        result["autoexec_keyword_count"] = len(autoexec_keywords)
        result["suspicious_keywords_list"] = suspicious_keywords
        result["autoexec_keywords_list"] = autoexec_keywords

    except Exception as e:
        result["error"] = f"VBA_analysis_error: {e}"
    finally:
        vba.close()

    return result


def process_single_file(file_path: str, label: str) -> dict:
    """
    label: 'malicious' or 'benign'
    """
    info = get_file_basic_info(file_path)
    vba_features = extract_vba_features(file_path)

    # Merge dictionaries
    record = {
        "label": label,
        **info,
        **vba_features,
    }

    # Save per-file JSON
    json_name = os.path.basename(file_path) + ".json"
    json_path = os.path.join(OUTPUT_DIR, json_name)

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(record, jf, ensure_ascii=False, indent=2)

    print(f"[OK] Processed {file_path}")
    return record


def iter_docs_in_folder(folder_path: str):
    """
    Yield doc/docx file paths under folder_path (recursive).
    """
    for root, dirs, files in os.walk(folder_path):
        for fname in files:
            if fname.lower().endswith((".doc", ".docx")):
                yield os.path.join(root, fname)


def main():
    all_records = []

    for label in ["malicious", "benign"]:
        base_label_dir = os.path.join(DATA_ROOT, label)

        if not os.path.isdir(base_label_dir):
            print(f"[WARN] Folder not found for label '{label}': {base_label_dir}")
            continue

        for file_path in iter_docs_in_folder(base_label_dir):
            record = process_single_file(file_path, label)
            all_records.append(record)

    # ---- Write summary CSV ----
    if not all_records:
        print("[ERROR] No files processed, check your folder paths.")
        return

    csv_path = os.path.join(OUTPUT_DIR, "results_summary.csv")

    # Use keys from first record as header
    fieldnames = list(all_records[0].keys())

    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)

    print(f"\n[DONE] Total files processed: {len(all_records)}")
    print(f"[INFO] Summary CSV: {csv_path}")
    print(f"[INFO] Per-file JSONs in: {OUTPUT_DIR}")


if __name__ == "__main__":
    print(f"Batch extraction started at {datetime.now()}")
    main()
    print(f"Finished at {datetime.now()}")
