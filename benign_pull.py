import os
import re
import urllib.parse

import requests
from bs4 import BeautifulSoup

# Pages that contain links to sample .doc / .docx files
BASE_PAGES = [
    "https://file-examples.com/index.php/sample-documents-download/sample-doc-download/",
    "https://filesamples.com/formats/docx",
    "https://www.learningcontainer.com/sample-docx-file-for-testing/",
    "https://freetestdata.com/document-files/docx/",
    "https://examplefiles.org/example-document-files/sample-word-document-files",
    "https://example-files.com/sample-doc-download/",
    "https://file.fyicenter.com/61_DOCX-File_Extension_for_Word_Document_XML_Files.html",
    "https://fluent.apryse.com/documentation/sample-template-libary",
    "https://accessibility.psu.edu/news/",
]


def find_doc_links(page_url: str):
    """
    Fetch a page and return all .doc / .docx links found on it.
    """
    print(f"[INFO] Scanning page: {page_url}")
    resp = requests.get(page_url, timeout=15)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    links = set()

    for a in soup.find_all("a", href=True):
        href = a["href"]
        # Normalize to absolute URL
        full_url = urllib.parse.urljoin(page_url, href)
        if full_url.lower().endswith((".doc", ".docx")):
            links.add(full_url)

    print(f"[INFO] Found {len(links)} doc/docx links on this page.")
    return links


def download_files(urls, out_dir="benign_docs", max_files=None):
    """
    Download .doc / .docx files from the given URLs into out_dir.
    """
    os.makedirs(out_dir, exist_ok=True)
    downloaded = []

    for url in sorted(urls):
        if max_files is not None and len(downloaded) >= max_files:
            break

        print(f"[DOWNLOAD] {url}")
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            print(f"[WARN] Skipping {url} -> {e}")
            continue

        # Derive filename from URL
        path_part = urllib.parse.urlparse(url).path
        filename = os.path.basename(path_part) or "file"
        base_name, ext = os.path.splitext(filename)

        # Ensure unique filename
        save_path = os.path.join(out_dir, filename)
        idx = 1
        while os.path.exists(save_path):
            save_path = os.path.join(out_dir, f"{base_name}_{idx}{ext}")
            idx += 1

        with open(save_path, "wb") as f:
            f.write(resp.content)

        downloaded.append(save_path)
        print(f"[OK] Saved to {save_path}")

    print(f"[INFO] Total downloaded files: {len(downloaded)}")
    return downloaded


def main():
    all_links = set()

    for page in BASE_PAGES:
        try:
            links = find_doc_links(page)
            all_links.update(links)
        except Exception as e:
            print(f"[WARN] Could not scan {page} -> {e}")

    print(f"[INFO] Total unique .doc/.docx URLs collected: {len(all_links)}")

    # Adjust max_files as you like (e.g. 100, 200, etc.)
    download_files(all_links, out_dir="benign_docs", max_files=200)


if __name__ == "__main__":
    main()
