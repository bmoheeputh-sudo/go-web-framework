#!/usr/bin/env python3
"""Update Git-tracked source files in Google Drive."""

import mimetypes
import os
import subprocess
from pathlib import Path

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

ROOT = Path(__file__).resolve().parent.parent
KEY = ROOT.parent / "secure/google/0.json"
FOLDER_ID = "1rwOlHtHd2ogU0Wv5_K454HbmXSGjxYPs"
USER = "bhoshan.moheeputh@vopak.com"
SCOPE = "https://www.googleapis.com/auth/drive"
FOLDER_MIME = "application/vnd.google-apps.folder"

credentials = service_account.Credentials.from_service_account_file(
    str(KEY), scopes=[SCOPE], subject=USER
)
drive = build("drive", "v3", credentials=credentials)

def find_file(name, parent):
    escaped = name.replace("\\", "\\\\").replace("'", "\\'")
    q = f"name = '{escaped}' and '{parent}' in parents and trashed = false"
    matches = []
    page = None

    while True:
        result = drive.files().list(
            q=q,
            fields="nextPageToken,files(id,name,mimeType)",
            pageToken=page,
            pageSize=100,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        ).execute()
        matches.extend(result.get("files", []))
        page = result.get("nextPageToken")
        if not page:
            break

    if len(matches) > 1:
        raise RuntimeError(f"Duplicate files named {name} in folder {parent}")
    return matches[0] if matches else None

def ensure_folder(name, parent):
    existing = find_file(name, parent)
    if existing:
        if existing["mimeType"] != FOLDER_MIME:
            raise RuntimeError(f"{name} exists but is not a folder")
        return existing["id"]

    created = drive.files().create(
        body={
            "name": name,
            "mimeType": FOLDER_MIME,
            "parents": [parent],
        },
        fields="id",
        supportsAllDrives=True,
    ).execute()
    print(f"Created folder: {name}")
    return created["id"]

def upload_file(path, parent):
    existing = find_file(path.name, parent)
    mime = mimetypes.guess_type(path.name)[0] or "text/plain"
    media = MediaFileUpload(str(path), mimetype=mime, resumable=True)

    if existing:
        if existing["mimeType"] == FOLDER_MIME:
            raise RuntimeError(f"{path.name} is a folder in Drive")
        if existing["mimeType"].startswith("application/vnd.google-apps."):
            raise RuntimeError(f"Cannot overwrite Google native file: {path.name}")

        drive.files().update(
            fileId=existing["id"],
            media_body=media,
            supportsAllDrives=True,
        ).execute()
        print(f"Updated: {path.relative_to(ROOT)}")
    else:
        drive.files().create(
            body={"name": path.name, "parents": [parent]},
            media_body=media,
            fields="id",
            supportsAllDrives=True,
        ).execute()
        print(f"Created: {path.relative_to(ROOT)}")

def main():
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
    ).decode().split("\0")

    folders = {"": FOLDER_ID}
    count = 0

    for relative in sorted(filter(None, tracked)):
        path = ROOT / relative

        if not path.is_file() or path.is_symlink():
            continue

        parts = Path(relative).parts
        if any(p.startswith(".env") or p in {
            ".git", ".venv", "node_modules", "secure", "__pycache__"
        } for p in parts):
            continue
        if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            continue
        if "service-account" in path.name.lower():
            continue

        parent = FOLDER_ID
        current = ""
        for part in parts[:-1]:
            current = f"{current}/{part}".strip("/")
            if current not in folders:
                folders[current] = ensure_folder(part, parent)
            parent = folders[current]

        upload_file(path, parent)
        count += 1

    print(f"Google Drive synchronization complete: {count} files")

if __name__ == "__main__":
    main()
