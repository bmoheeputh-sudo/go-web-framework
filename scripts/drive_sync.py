#!/usr/bin/env python3
"""Incrementally back up committed, tracked source files (preview by default)."""

import argparse
from contextlib import contextmanager
import errno
import fcntl
import http.client
import io
import json
import mimetypes
import os
from pathlib import Path, PurePosixPath
import re
import socket
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
KEY = ROOT.parent / "secure/google/0.json"
FOLDER_ID = "1rwOlHtHd2ogU0Wv5_K454HbmXSGjxYPs"
USER = "bhoshan.moheeputh@vopak.com"
SCOPE = "https://www.googleapis.com/auth/drive"
FOLDER_MIME = "application/vnd.google-apps.folder"
STATE = Path.home() / ".config/go-web-framework/drive-sync-state.json"
FIELDS = "id,name,mimeType,parents,trashed"
ATTEMPTS = 5
HTTP_TIMEOUT = 120


class SyncError(RuntimeError):
    """A safe, user-facing error that contains no authentication data."""


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE)


def snapshot(root, commit):
    entries = {}
    for entry in git(root, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            entries[name.decode("utf-8")] = (mode, kind, oid)
    return entries


def changes(root, base, target, entries):
    if base is None:
        return [("A", name, None) for name in sorted(entries)]
    if not re.fullmatch(r"[0-9a-f]{40,64}", base):
        raise SyncError("Invalid checkpoint commit; state was not changed.")
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, target],
                      cwd=root, capture_output=True).returncode:
        raise SyncError("Checkpoint is missing or history was rewritten. Restore history or "
                        "archive the state file to start a full reconciliation.")
    tokens = git(root, "diff", "--name-status", "-z", "--find-renames",
                 base, target, "--").decode("utf-8").split("\0")
    result = []
    index = 0
    while tokens[index]:
        status, name = tokens[index:index + 2]
        index += 2
        old = None
        if status.startswith("R"):
            old, name = name, tokens[index]
            index += 1
        result.append((status[0], name, old))
    return result


EXCLUDED_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "secure", "secrets",
    "credentials", ".ssh", ".aws", ".gnupg", "__pycache__", ".pytest_cache",
    "bin", "build", "dist", "target", ".next", ".terraform",
}
EXCLUDED_SUFFIXES = {
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".crt", ".ppk", ".der",
    ".pyc", ".pyo", ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".class", ".jar", ".wasm", ".out", ".log", ".db", ".sqlite", ".sqlite3",
    ".zip", ".tar", ".gz", ".7z", ".bak", ".pickle", ".pkl", ".tfstate", ".kdbx",
}


def excluded(name):
    parts = PurePosixPath(name).parts
    return any(
        p.lower() in EXCLUDED_DIRS
        or p.lower().startswith((".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"))
        or any(word in p.lower() for word in ("credential", "service-account", "service_account", "secret"))
        or p.lower() in {".netrc", ".npmrc", ".pypirc", "token.json", "tokens.json"}
        for p in parts
    ) or PurePosixPath(name).suffix.lower() in EXCLUDED_SUFFIXES


def validate_path(root, name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
            or str(path) != name or any(ord(c) < 32 for c in name)):
        raise SyncError(f"Unsafe Git path: {name!r}")
    local = root
    for part in path.parts:
        local = local / part
        if local.is_symlink():
            raise SyncError(f"Refusing symlink in local path: {name!r}")
    if not local.resolve().is_relative_to(root.resolve()):
        raise SyncError(f"Path escapes repository: {name!r}")


def unsafe_content(data):
    # Defense in depth for accidentally tracked keys and extensionless executables.
    service_account = False
    if data.lstrip().startswith(b"{"):
        try:
            document = json.loads(data)
            service_account = isinstance(document, dict) and (
                document.get("type") == "service_account"
                or ("private_key" in document and "client_email" in document))
        except (ValueError, UnicodeDecodeError):
            pass
    return (bool(re.search(rb"(?m)^-----BEGIN [A-Z ]*PRIVATE KEY-----\r?$", data))
            or service_account
            or data.startswith((b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce",
                                b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                                b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")))


def load_state(path, root):
    if not path.exists():
        return {"version": 1, "repository": str(root.resolve()), "folder_id": FOLDER_ID,
                "last_commit": None, "pending_commit": None, "resources": {}}
    try:
        state = json.loads(path.read_text())
        if (state["version"] != 1 or state["repository"] != str(root.resolve())
                or state["folder_id"] != FOLDER_ID or not isinstance(state["resources"], dict)):
            raise ValueError
        for key in ("last_commit", "pending_commit"):
            if state[key] is not None and not re.fullmatch(r"[0-9a-f]{40,64}", state[key]):
                raise ValueError
        for entry in state["resources"].values():
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                raise ValueError
        return state
    except (ValueError, KeyError, TypeError):
        raise SyncError("Invalid state or state belongs to another repository/destination.") from None


def save_state(path, state):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".drive-sync-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def state_lock(path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SyncError("Another Drive synchronization is running.") from None
        yield


def status_code(error):
    return getattr(getattr(error, "resp", None), "status", None)


def transient(error):
    # Lazy imports keep preview and Git planning usable without Google packages.
    from google.auth.exceptions import TransportError
    import httplib2
    return (status_code(error) in {408, 429, 500, 502, 503, 504}
            or (isinstance(status_code(error), int) and 500 <= status_code(error) < 600)
            or (isinstance(error, OSError) and error.errno in {
                errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH,
                errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, errno.ENETRESET})
            or isinstance(error, (TimeoutError, ConnectionError, socket.gaierror,
                                  ssl.SSLError, http.client.HTTPException,
                                  httplib2.HttpLib2Error, TransportError)))


def execute(factory, sleep=time.sleep):
    for attempt in range(ATTEMPTS):
        try:
            return factory().execute(num_retries=0)
        except Exception as error:
            if not transient(error) or attempt == ATTEMPTS - 1:
                raise
            delay = 2 ** attempt
            print(f"Transient API failure; retry {attempt + 1}/{ATTEMPTS - 1} in {delay}s")
            sleep(delay)


def build_drive():
    from google.oauth2 import service_account
    from google_auth_httplib2 import AuthorizedHttp
    from googleapiclient.discovery import build
    import httplib2
    credentials = service_account.Credentials.from_service_account_file(
        str(KEY), scopes=[SCOPE], subject=USER)
    http = AuthorizedHttp(credentials, http=httplib2.Http(timeout=HTTP_TIMEOUT))
    return build("drive", "v3", http=http, cache_discovery=False)


def media(data, name):
    from googleapiclient.http import MediaIoBaseUpload
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    return MediaIoBaseUpload(io.BytesIO(data), mimetype=mime, resumable=False)


class Synchronizer:
    def __init__(self, root, state_path, drive, sleep=time.sleep):
        self.root, self.state_path, self.drive, self.sleep = root, state_path, drive, sleep
        self.state = load_state(state_path, root)
        self.folders = {"": FOLDER_ID}

    def save(self):
        save_state(self.state_path, self.state)

    def call(self, factory):
        return execute(factory, self.sleep)

    def find(self, name, parent):
        def escape(value):
            return value.replace("\\", "\\\\").replace("'", "\\'")
        query = f"name = '{escape(name)}' and '{escape(parent)}' in parents and trashed = false"
        matches, page = [], None
        while True:
            result = self.call(lambda: self.drive.files().list(
                q=query, fields=f"nextPageToken,files({FIELDS})", pageToken=page,
                pageSize=100, supportsAllDrives=True, includeItemsFromAllDrives=True))
            matches.extend(result.get("files", []))
            page = result.get("nextPageToken")
            if not page:
                break
        if len(matches) > 1:
            raise SyncError(f"Ambiguous Drive filename: {name!r} (multiple matches).")
        return matches[0] if matches else None

    def get(self, file_id):
        try:
            return self.call(lambda: self.drive.files().get(
                fileId=file_id, fields=FIELDS, supportsAllDrives=True))
        except Exception as error:
            if status_code(error) == 404:
                return None
            raise

    def put(self, relative, parent, data=None, blob=None, old=None):
        """Upsert by ID. Journal generated IDs before any potentially ambiguous create."""
        folder = data is None
        key = relative + "/" if folder else relative
        name = PurePosixPath(relative).name
        resources = self.state["resources"]
        record = resources.get(key)
        if record is None and old and not excluded(old):
            record = resources.get(old)
        existing = self.find(name, parent)  # Always detect collisions, including on retry.
        if record and existing and existing["id"] != record["id"]:
            raise SyncError(f"Drive ID/name conflict for {relative!r}.")
        if record and not existing:
            existing = self.get(record["id"])
        if existing:
            mime = existing["mimeType"]
            if existing.get("trashed") or (folder and mime != FOLDER_MIME) or (
                    not folder and mime.startswith("application/vnd.google-apps.")):
                raise SyncError(f"Incompatible or trashed Drive item: {relative!r}.")
            # Only an explicitly detected Git rename may move an existing resource.
            if (existing["name"] != name or parent not in existing.get("parents", [])) and not old:
                raise SyncError(f"Drive item moved externally: {relative!r}.")
        if record is None:
            file_id = existing["id"] if existing else self.call(
                lambda: self.drive.files().generateIds(count=1, space="drive"))["ids"][0]
            record = {"id": file_id}
        resources[key] = dict(record)
        self.save()
        file_id = record["id"]
        action = "updated" if existing else "created"
        if not existing:
            body = {"id": file_id, "name": name, "parents": [parent]}
            if folder:
                body["mimeType"] = FOLDER_MIME
            try:
                self.call(lambda: self.drive.files().create(
                    body=body, fields=FIELDS, supportsAllDrives=True,
                    **({} if folder else {"media_body": media(data, name)})))
            except Exception as error:
                if status_code(error) != 409:
                    raise
                # A timed-out create may already have succeeded. Never allocate a new ID.
                existing = self.get(file_id)
                if (not existing or existing.get("trashed") or existing["name"] != name
                        or parent not in existing.get("parents", [])
                        or (folder and existing["mimeType"] != FOLDER_MIME)
                        or (not folder and existing["mimeType"].startswith("application/vnd.google-apps."))):
                    raise SyncError(f"Cannot verify retried create for {relative!r}.") from None
        if existing and not folder:
            same_location = existing["name"] == name and parent in existing.get("parents", [])
            if record.get("blob") == blob and same_location:
                action = "skipped"
            else:
                move = {}
                if parent not in existing.get("parents", []):
                    move = {"addParents": parent, "removeParents": ",".join(existing.get("parents", []))}
                self.call(lambda: self.drive.files().update(
                    fileId=file_id, body={"name": name}, media_body=media(data, name),
                    fields=FIELDS, supportsAllDrives=True, **move))
        if not folder:
            resources[key]["blob"] = blob
            if old and old != key and resources.get(old, {}).get("id") == file_id:
                del resources[old]
        self.save()
        return file_id, action

    def parent(self, relative):
        current, parent = "", FOLDER_ID
        for part in PurePosixPath(relative).parts[:-1]:
            current = f"{current}/{part}".lstrip("/")
            if current not in self.folders:
                self.folders[current] = self.put(current, parent)[0]
            parent = self.folders[current]
        return parent

    def sync(self, target):
        entries = snapshot(self.root, target)
        plan = changes(self.root, self.state["last_commit"], target, entries)
        changed = {name for _, name, _ in plan}
        counts = {"created": 0, "updated": 0, "skipped": len(set(entries) - changed), "failed": 0}
        self.state["pending_commit"] = target
        self.save()
        for status, name, old in plan:
            try:
                if status == "D":
                    print(f"Retained deleted file: {name!r}")
                    counts["skipped"] += 1
                    continue
                mode, kind, oid = entries[name]
                if excluded(name) or kind != "blob" or mode not in {"100644", "100755"}:
                    print(f"Skipped excluded/non-regular file: {name!r}")
                    counts["skipped"] += 1
                    continue
                validate_path(self.root, name)
                data = git(self.root, "cat-file", "blob", oid)
                if unsafe_content(data):
                    print(f"Skipped sensitive/binary content: {name!r}")
                    counts["skipped"] += 1
                    continue
                _, action = self.put(name, self.parent(name), data, oid, old)
                counts[action] += 1
                print(f"{action.capitalize()}: {name!r}")
            except Exception as error:
                counts["failed"] += 1
                print(f"Failed: {name!r}: {safe_error(error)}")
        print("Summary: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        if counts["failed"]:
            raise SyncError("Drive sync incomplete; checkpoint unchanged. Rerun to retry pending changes.")
        self.state["last_commit"] = target
        self.state["pending_commit"] = None
        self.save()
        return counts


def safe_error(error):
    # Google exceptions can contain response bodies/URLs. Never dump them or credentials.
    if isinstance(error, SyncError):
        return str(error)
    code = status_code(error)
    return f"HTTP {code}" if code else type(error).__name__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", action="store_true", help="Perform a live sync (asks for approval).")
    parser.add_argument("--yes", action="store_true", help="Approval already obtained by backup.sh.")
    args = parser.parse_args()
    try:
        head = git(ROOT, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        if STATE.resolve().is_relative_to(ROOT.resolve()):
            raise SyncError("Synchronization state must be outside the repository.")
        state = load_state(STATE, ROOT)
        targets = list(dict.fromkeys(filter(None, [state["pending_commit"], head])))
        base = state["last_commit"]
        for target in targets:
            entries = snapshot(ROOT, target)
            plan = changes(ROOT, base, target, entries)
            print(f"Commit {target}: {len(plan)} Git changes (security exclusions apply)")
            for status, name, old in plan:
                print(f"  {status} {old!r} -> {name!r}" if old else f"  {status} {name!r}")
            base = target
        if not args.sync:
            print("Preview only; no credentials loaded, state written, or API calls made.")
            return 0
        if not args.yes and input("Synchronize these commits to Google Drive? [y/N] ").lower() != "y":
            return 1
        with state_lock(STATE):
            sync = Synchronizer(ROOT, STATE, build_drive())
            targets = list(dict.fromkeys(filter(None, [sync.state["pending_commit"], head])))
            for target in targets:
                sync.sync(target)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"Drive synchronization stopped: {safe_error(error)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
