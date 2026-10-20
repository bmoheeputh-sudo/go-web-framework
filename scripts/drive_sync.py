#!/usr/bin/env python3
"""Incrementally back up committed, tracked source files (preview by default)."""

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import hashlib
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
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
KEY = ROOT.parent / "secure/google/0.json"
FOLDER_ID = "1rwOlHtHd2ogU0Wv5_K454HbmXSGjxYPs"
USER = "bhoshan.moheeputh@vopak.com"
SCOPE = "https://www.googleapis.com/auth/drive"
FOLDER_MIME = "application/vnd.google-apps.folder"
STATE = Path.home() / ".config/go-web-framework/drive-sync-state.json"
FIELDS = "id,name,mimeType,parents,trashed,explicitlyTrashed,appProperties,md5Checksum,size,version"
ATTEMPTS = 5
HTTP_TIMEOUT = 120
DEFAULT_WORKERS = 5
MAX_WORKERS = 8


class SyncError(RuntimeError):
    """A safe, user-facing error that contains no authentication data."""


class Conflict(SyncError):
    """A resource needs investigation rather than a guessed repair."""


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
        if (state["version"] not in {1, 2} or state["repository"] != str(root.resolve())
                or state["folder_id"] != FOLDER_ID or not isinstance(state["resources"], dict)):
            raise ValueError
        if state["version"] == 2 and not re.fullmatch(r"[0-9a-f]{32}", state.get("backup_id", "")):
            raise ValueError
        for key in ("last_commit", "pending_commit"):
            if state[key] is not None and not re.fullmatch(r"[0-9a-f]{40,64}", state[key]):
                raise ValueError
        for name, entry in state["resources"].items():
            if (not isinstance(name, str) or not isinstance(entry, dict)
                    or not isinstance(entry.get("id"), str) or not entry["id"]):
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


def ancestor(root, base, target):
    if not re.fullmatch(r"[0-9a-f]{40,64}", target):
        raise SyncError("Invalid target commit.")
    if base is not None:
        changes(root, base, target, {})


def targets_for(root, state, head):
    targets = list(dict.fromkeys(filter(None, [state["pending_commit"], head])))
    base = state["last_commit"]
    # Validate the entire chain before replaying even one older operation.
    for target in targets:
        ancestor(root, base, target)
        base = target
    return targets


def eligible_blob(root, name, entry):
    if excluded(name) or entry[1] != "blob" or entry[0] not in {"100644", "100755"}:
        return False
    validate_path(root, name)
    return not unsafe_content(git(root, "cat-file", "blob", entry[2]))


@dataclass(frozen=True)
class Operation:
    kind: str
    name: str
    oid: str = None
    old: str = None
    reason: str = ""


def location(state, name):
    parent_path = str(PurePosixPath(name.rstrip("/")).parent)
    if parent_path == ".":
        return FOLDER_ID
    record = state["resources"].get(parent_path + "/", {})
    if not record.get("id"):
        raise Conflict(f"Missing recorded parent for {name!r}; manual review required.")
    return record["id"]


def deletion_proof(record):
    # Under the approved mirror policy, adopted files are managed too, but an ID
    # alone is insufficient. Content and the full hierarchy must also be checked.
    return bool(record and record.get("blob") and (
        record.get("origin") in {None, "adopted"}
        or (record.get("origin") == "created" and record.get("creation_token"))))


def plan_sync(root, state, target):
    entries = snapshot(root, target)
    base = state["last_commit"]
    diff = changes(root, base, target, entries)
    previous = snapshot(root, base) if base else {}
    operations = []
    changed = {name for _, name, _ in diff}
    # Overlapping rename chains need a separate path journal; refuse rather than
    # lose an original mapping if interrupted between reservations.
    destinations = {name for status, name, _ in diff if status != "D"}
    overlaps = {old for status, _, old in diff if status == "R" and old in destinations}
    for status, name, old in diff:
        try:
            source = previous.get(name) if status == "D" else entries.get(name)
            if not source or not eligible_blob(root, name, source):
                operations.append(Operation("skipped", name, reason="Excluded/non-regular or sensitive content"))
                continue
            if old in overlaps or name in overlaps:
                raise Conflict("Overlapping rename paths require manual reconciliation.")
            if status == "D":
                record = state["resources"].get(name)
                if not deletion_proof(record):
                    raise Conflict("No completed managed-file/content record; manual review required.")
                if record["blob"] != source[2]:
                    raise Conflict("Deletion journal does not match the last synchronized Git content.")
                operations.append(Operation("trash", name, source[2]))
            else:
                if old and (old not in previous or not eligible_blob(root, old, previous[old])):
                    # A rename from an excluded source must never acquire its ID.
                    old = None
                record = state["resources"].get(name) or state["resources"].get(old)
                kind = "rename" if old else "update" if record and not record.get("trashed") else "create"
                if record and not record.get("intent") and not record.get("trashed") and record.get("blob") == source[2] and not old:
                    kind = "unchanged"
                operations.append(Operation(kind, name, source[2], old))
        except SyncError as error:
            operations.append(Operation("blocked", name, old=old, reason=str(error)))
    # Untouched tracked files are not uploaded, scanned or fetched from Drive.
    unchanged = sum(1 for name, entry in entries.items()
                    if name not in changed and not excluded(name)
                    and entry[1] == "blob" and entry[0] in {"100644", "100755"})
    return operations, unchanged


def print_preview(root, state, head):
    state = copy.deepcopy(state)
    for target in targets_for(root, state, head):
        operations, unchanged = plan_sync(root, state, target)
        counts = {key: 0 for key in ("create", "update", "unchanged", "rename", "trash", "blocked", "skipped")}
        counts["unchanged"] = unchanged
        print(f"Commit {target}:")
        for op in operations:
            counts[op.kind] += 1
            print(f"  {op.kind}: {op.old!r} -> {op.name!r}" if op.old else f"  {op.kind}: {op.name!r}")
            if op.reason:
                print(f"    {op.reason}")
        print("Plan: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        # Preview is an estimate from the local journal, never a remote assurance.
        state["last_commit"] = target
    print("Drive identity, content and location conflicts are verified during an approved sync.")


class DriveClient:
    """One client/HTTP transport, used by exactly one thread."""

    def __init__(self, drive, sync):
        self.drive, self.sync = drive, sync

    def call(self, factory):
        return execute(factory, self.sync.sleep)

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
            raise Conflict(f"Ambiguous Drive filename: {name!r} (multiple matches).")
        return matches[0] if matches else None

    def get(self, file_id):
        headers = {}

        def request():
            headers.clear()
            req = self.drive.files().get(fileId=file_id, fields=FIELDS, supportsAllDrives=True)
            req.add_response_callback(lambda response: headers.update(response))
            return req
        try:
            item = self.call(request)
            item["_etag"] = headers.get("etag")
            return item
        except Exception as error:
            if status_code(error) == 404:
                return None
            raise

    def matches(self, item, record, name=None, parent=None, allow_trash=False):
        if not item or item.get("id") != record["id"]:
            raise Conflict("Recorded Drive resource is missing; manual review required.")
        if (item.get("name") != (name or record["name"])
                or item.get("parents") != [parent or record["parent"]]
                or item.get("mimeType") != record["mimeType"]
                or (item.get("trashed") and not allow_trash)):
            raise Conflict("Recorded Drive resource was renamed, moved, replaced or trashed externally.")
        if record.get("origin") == "created":
            props = item.get("appProperties", {})
            if (props.get("gwf_backup") != self.sync.state["backup_id"]
                    or props.get("gwf_resource") != record.get("creation_token")):
                raise Conflict("Drive creation/ownership markers do not match the journal.")
        return item

    def confirmed(self, item, record, intent, data):
        self.matches(item, record, intent["name"], intent["parent"], intent["kind"] == "trash")
        if intent["kind"] == "trash":
            if item.get("trashed") is not True or item.get("explicitlyTrashed") is not True:
                raise Conflict("Drive Trash outcome could not be confirmed.")
        elif data is not None and (item.get("md5Checksum") != intent["md5"]
                                   or str(item.get("size")) != str(len(data))):
            raise Conflict("Drive upload content could not be confirmed.")
        return item

    def write(self, record, intent, create=False, data=None):
        """Never repeat a mutation before an authoritative GET reconciles it."""
        for attempt in range(ATTEMPTS):
            item = self.get(record["id"])
            if item:
                props = item.get("appProperties", {})
                if props.get("gwf_write") == intent["token"]:
                    return self.confirmed(item, record, intent, data)
                self.matches(item, record, allow_trash=intent["kind"] == "trash")
                if create:
                    raise Conflict("Reserved Drive ID already exists without this operation's write marker.")
                if record.get("version") and str(item.get("version")) != record["version"]:
                    raise Conflict("Drive resource changed after the journaled operation was prepared.")
                if intent["kind"] == "trash":
                    if item.get("md5Checksum") != intent["md5"]:
                        raise Conflict("Drive content changed; refusing to trash the resource.")
                    if item.get("trashed"):
                        if item.get("explicitlyTrashed") is not True:
                            raise Conflict("Drive file is in Trash through its parent; manual review required.")
                        return item
                if not item.get("_etag"):
                    raise Conflict("Drive did not provide an ETag; refusing an unguarded update.")
            elif not create:
                raise Conflict("Recorded Drive resource is missing; no replacement will be adopted.")
            body = {"name": intent["name"], "mimeType": record["mimeType"],
                    "appProperties": {"gwf_write": intent["token"]}}
            if create:
                body.update(id=record["id"], parents=[intent["parent"]])
                body["appProperties"].update(gwf_backup=self.sync.state["backup_id"],
                                              gwf_resource=record["creation_token"])
            if data is not None:
                body["appProperties"]["gwf_blob"] = intent["blob"]
            if intent["kind"] == "trash":
                body = {"trashed": True, "appProperties": {"gwf_write": intent["token"]}}
            args = dict(body=body, fields=FIELDS, supportsAllDrives=True)
            if data is not None:
                args["media_body"] = media(data, intent["name"])
            try:
                if create:
                    req = self.drive.files().create(**args)
                else:
                    move = {}
                    if intent["parent"] != record["parent"]:
                        move = dict(addParents=intent["parent"], removeParents=record["parent"])
                    req = self.drive.files().update(fileId=record["id"], **args, **move)
                    req.headers["If-Match"] = item["_etag"]
                req.execute(num_retries=0)
            except Exception as error:
                # Even the final timed-out operation may have succeeded.
                if not transient(error) and status_code(error) != 409:
                    if status_code(error) == 412:
                        raise Conflict("Drive changed before the conditional write; manual review required.") from None
                    raise
                confirmed = self.get(record["id"])
                if confirmed and confirmed.get("appProperties", {}).get("gwf_write") == intent["token"]:
                    return self.confirmed(confirmed, record, intent, data)
                if attempt == ATTEMPTS - 1:
                    raise
                self.sync.sleep(2 ** attempt)
                continue
            confirmed = self.get(record["id"])
            if (not confirmed
                    or confirmed.get("appProperties", {}).get("gwf_write") != intent["token"]):
                raise Conflict("Drive write could not be confirmed; operation remains pending.")
            return self.confirmed(confirmed, record, intent, data)

    def put(self, relative, parent, target, data=None, blob=None, old=None):
        folder = data is None
        key = relative + "/" if folder else relative
        name = PurePosixPath(relative).name
        record = self.sync.record(key)
        prior = self.sync.record(old) if old else None
        if prior and record and prior["id"] != record["id"]:
            raise Conflict(f"Conflicting rename records for {relative!r}.")
        record = record or prior
        if record and record.get("commit"):
            ancestor(self.sync.root, record["commit"], target)
        collision = self.find(name, parent)
        if collision and record and collision["id"] != record["id"]:
            raise Conflict(f"Drive ID/name conflict for {relative!r}.")
        if record and record.get("trashed"):
            # Re-creation gets a fresh ID; never restore or reuse a tombstone.
            self.matches(self.get(record["id"]), record, allow_trash=True)
            if collision:
                raise Conflict("A different live resource occupies a previously deleted path.")
            record = None
        if record is None:
            if collision:
                item = self.get(collision["id"])
                record = {"id": collision["id"], "origin": "adopted",
                          "name": name, "parent": parent, "mimeType": item["mimeType"]}
            else:
                record = {"id": self.call(lambda: self.drive.files().generateIds(count=1, space="drive"))["ids"][0],
                          "origin": "created", "creation_token": uuid.uuid4().hex,
                          "name": name, "parent": parent,
                          "mimeType": FOLDER_MIME if folder else mimetypes.guess_type(name)[0] or "application/octet-stream"}
        if (folder and record.get("mimeType", FOLDER_MIME) != FOLDER_MIME):
            raise Conflict(f"Incompatible Drive folder: {relative!r}.")
        if not folder and record.get("mimeType", "").startswith("application/vnd.google-apps."):
            raise Conflict(f"Incompatible Drive file: {relative!r}.")
        create = record.get("origin") == "created" and not record.get("blob") and not record.get("complete")
        intent = record.get("intent")
        if intent:
            if (intent["commit"] != target or intent["kind"] not in {"create", "update"}
                    or intent["name"] != name or intent["parent"] != parent or intent.get("blob") != blob):
                raise Conflict("Pending write does not match this commit; manual review required.")
            create = intent["kind"] == "create"
        else:
            item = None if create else self.get(record["id"])
            if not create:
                if not item:
                    raise Conflict(f"Recorded Drive resource is missing: {relative!r}.")
                # Version-1 records lack location metadata; derive it from the
                # recorded Git path/parent, never an arbitrary filename result.
                if "name" not in record:
                    source = old or relative
                    record.update(origin="adopted", name=PurePosixPath(source).name,
                                  parent=self.sync.recorded_parent(source),
                                  mimeType=item["mimeType"])
                    if old and item.get("name") == name and item.get("parents") == [parent]:
                        record.update(name=name, parent=parent)
                if ((folder and record["mimeType"] != FOLDER_MIME)
                        or (not folder and record["mimeType"].startswith("application/vnd.google-apps."))):
                    raise Conflict(f"Incompatible Drive resource type: {relative!r}.")
                if not old and (record["name"] != name or record["parent"] != parent):
                    raise Conflict("Recorded path disagrees with Git; only a Git rename may move a file.")
                self.matches(item, record)
                if folder:
                    record.update(complete=True, version=str(item.get("version", "")), commit=target)
                    self.sync.journal(key, record)
                    return record["id"], "skipped"
                if record.get("blob") == blob and record["name"] == name and record["parent"] == parent:
                    if item.get("md5Checksum") != hashlib.md5(data).hexdigest():
                        raise Conflict("Unchanged Git blob has different Drive content.")
                    record.update(version=str(item.get("version", "")), commit=target)
                    self.sync.journal(key, record, old)
                    return record["id"], "skipped"
                record["version"] = str(item.get("version", ""))
            intent = {"kind": "create" if create else "update", "commit": target,
                      "token": uuid.uuid4().hex, "name": name, "parent": parent, "blob": blob}
            if not folder:
                intent["md5"] = hashlib.md5(data).hexdigest()
            record["intent"] = intent
            self.sync.journal(key, record)
        item = self.write(record, intent, create=create, data=data)
        record.update(name=name, parent=parent, complete=True, commit=target,
                      version=str(item.get("version", "")))
        record.pop("intent", None)
        if not folder:
            record.update(blob=blob, md5=hashlib.md5(data).hexdigest())
        self.sync.journal(key, record, old)
        return record["id"], "created" if create else "renamed" if old else "updated"

    def trash(self, op, target):
        record = self.sync.record(op.name)
        if not deletion_proof(record):
            raise Conflict("No completed managed-file/content record; manual review required.")
        if record.get("commit"):
            ancestor(self.sync.root, record["commit"], target)
        self.sync.verify_ancestors(op.name)
        data = git(self.sync.root, "cat-file", "blob", record["blob"])
        if unsafe_content(data):
            raise Conflict("Recorded content is excluded; refusing to trash it.")
        item = self.get(record["id"])
        if not item:
            raise Conflict("Recorded deletion resource is missing; manual review required.")
        if "name" not in record:
            expected_mime = mimetypes.guess_type(op.name)[0] or "application/octet-stream"
            record.update(origin="adopted", name=PurePosixPath(op.name).name,
                          parent=self.sync.recorded_parent(op.name), mimeType=expected_mime)
        if (record["name"] != PurePosixPath(op.name).name
                or record["parent"] != self.sync.recorded_parent(op.name)):
            raise Conflict("Deletion journal path disagrees with Git; manual review required.")
        if record["mimeType"].startswith("application/vnd.google-apps."):
            raise Conflict("Refusing to trash folders or native Google resources.")
        self.matches(item, record, allow_trash=True)
        checksum = hashlib.md5(data).hexdigest()
        if item.get("md5Checksum") != checksum:
            raise Conflict("Recorded deletion content differs from Drive; manual review required.")
        intent = record.get("intent")
        if intent and (intent["kind"] != "trash" or intent["commit"] != target):
            raise Conflict("An earlier write is unresolved; refusing to trash this file.")
        if not intent:
            record["version"] = str(item.get("version", ""))
            intent = {"kind": "trash", "commit": target, "token": uuid.uuid4().hex,
                      "name": record["name"], "parent": record["parent"], "md5": checksum}
            record["intent"] = intent
            self.sync.journal(op.name, record)
        if item.get("trashed"):
            if item.get("explicitlyTrashed") is not True:
                raise Conflict("File is only implicitly trashed through a parent.")
        else:
            item = self.write(record, intent)
        record.update(trashed=True, commit=target, version=str(item.get("version", "")))
        record.pop("intent", None)
        self.sync.journal(op.name, record)
        return "trashed"


class Synchronizer:
    def __init__(self, root, state_path, drive_factory=build_drive, sleep=time.sleep,
                 workers=DEFAULT_WORKERS):
        if not isinstance(workers, int) or not 1 <= workers <= MAX_WORKERS:
            raise SyncError(f"Worker count must be between 1 and {MAX_WORKERS}.")
        if state_path.resolve().is_relative_to(root.resolve()):
            raise SyncError("Synchronization state must be outside the repository.")
        self.root, self.state_path, self.drive_factory = root, state_path, drive_factory
        self.sleep, self.workers = sleep, workers
        self.state = load_state(state_path, root)
        self.mutex = threading.RLock()
        self.local = threading.local()
        self.clients = []
        self.coordinator = None
        self.folders = {"": FOLDER_ID}
        self.folder_errors = {}

    def client(self):
        if not hasattr(self.local, "client"):
            drive = self.drive_factory()
            with self.mutex:
                if any(client.drive is drive for client in self.clients):
                    raise SyncError("Drive client factory reused a client across threads.")
                client = DriveClient(drive, self)
                self.clients.append(client)
            self.local.client = client
        return self.local.client

    def record(self, key):
        with self.mutex:
            return copy.deepcopy(self.state["resources"].get(key))

    def recorded_parent(self, name):
        with self.mutex:
            return location(self.state, name)

    def journal(self, key, record, old=None):
        with self.mutex:
            self.state["resources"][key] = copy.deepcopy(record)
            if old and old != key and self.state["resources"].get(old, {}).get("id") == record["id"]:
                del self.state["resources"][old]
            save_state(self.state_path, self.state)

    def verify_ancestors(self, name):
        parent = FOLDER_ID
        root = self.coordinator.get(parent)
        if not root or root.get("mimeType") != FOLDER_MIME or root.get("trashed"):
            raise Conflict("Backup destination folder is missing, incompatible or trashed.")
        parts = PurePosixPath(name).parts[:-1]
        for index, part in enumerate(parts):
            key = "/".join(parts[:index + 1]) + "/"
            record = self.record(key)
            if not record:
                raise Conflict("Missing folder record; manual review required.")
            record.setdefault("name", part)
            record.setdefault("parent", parent)
            record.setdefault("mimeType", FOLDER_MIME)
            if record["name"] != part or record["parent"] != parent or record["mimeType"] != FOLDER_MIME:
                raise Conflict("Recorded folder hierarchy disagrees with Git.")
            self.coordinator.matches(self.coordinator.get(record["id"]), record)
            parent = record["id"]

    def parent(self, relative, target):
        current, parent = "", FOLDER_ID
        for part in PurePosixPath(relative).parts[:-1]:
            current = f"{current}/{part}".lstrip("/")
            if current in self.folder_errors:
                raise self.folder_errors[current]
            if current not in self.folders:
                try:
                    self.folders[current] = self.coordinator.put(current, parent, target)[0]
                except Exception as error:
                    self.folder_errors[current] = error
                    raise
            parent = self.folders[current]
        return parent

    def upload(self, op, parent, target):
        validate_path(self.root, op.name)
        data = git(self.root, "cat-file", "blob", op.oid)
        if unsafe_content(data):
            raise Conflict("Content became ineligible; upload refused.")
        return self.client().put(op.name, parent, target, data, op.oid, op.old)[1]

    def sync_snapshot(self, target):
        operations, unchanged = plan_sync(self.root, self.state, target)
        counts = dict(created=0, updated=0, renamed=0, trashed=0,
                      skipped=unchanged, blocked=0, failed=0)
        self.state["pending_commit"] = target
        save_state(self.state_path, self.state)
        uploads, deletions = [], []
        root_checked = False

        def failed(op, error):
            counts["failed"] += 1
            counts["blocked"] += isinstance(error, Conflict)
            print(f"Failed: {op.name!r}: {safe_error(error)}")

        # Only the coordinator touches folders. All parents are established
        # before dependent uploads are submitted.
        for op in operations:
            try:
                if op.kind == "blocked":
                    raise Conflict(op.reason)
                if op.kind == "skipped":
                    counts["skipped"] += 1
                    print(f"Skipped: {op.name!r} ({op.reason})")
                elif op.kind == "trash":
                    deletions.append(op)
                else:
                    if not root_checked:
                        self.coordinator = self.client()
                        self.verify_ancestors("root-file")
                        root_checked = True
                    if op.old:
                        self.verify_ancestors(op.old)
                    uploads.append((op, self.parent(op.name, target)))
            except Exception as error:
                failed(op, error)
        ids = {}
        for op, _ in uploads:
            record = self.record(op.name) or self.record(op.old)
            if record and record["id"] in ids:
                raise Conflict("Multiple upload paths share one Drive ID; manual review required.")
            if record:
                ids[record["id"]] = op.name
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="drive-sync") as pool:
            futures = {pool.submit(self.upload, op, parent, target): op for op, parent in uploads}
            for future in as_completed(futures):
                op = futures[future]
                try:
                    action = future.result()
                    counts[action] += 1
                    print(f"{action.capitalize()}: {op.name!r}")
                except Exception as error:
                    failed(op, error)
        for op in deletions:
            try:
                if self.coordinator is None:
                    self.coordinator = self.client()
                action = self.coordinator.trash(op, target)
                counts[action] += 1
                print(f"Trashed: {op.name!r}")
            except Exception as error:
                failed(op, error)
        print("Summary: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        if counts["failed"]:
            raise SyncError("Drive sync incomplete; checkpoint unchanged. Rerun to retry pending changes.")
        self.state["last_commit"] = target
        self.state["pending_commit"] = None
        save_state(self.state_path, self.state)
        return counts

    def sync(self, head):
        # The lock covers reload, migration, every pending/new snapshot and all
        # worker cleanup. Library users receive the same protection as the CLI.
        with state_lock(self.state_path):
            self.state = load_state(self.state_path, self.root)
            targets = targets_for(self.root, self.state, head)
            self.state.update(version=2, backup_id=self.state.get("backup_id") or uuid.uuid4().hex)
            self.local, self.clients, self.coordinator = threading.local(), [], None
            try:
                result = None
                for target in targets:
                    self.folders, self.folder_errors = {"": FOLDER_ID}, {}
                    result = self.sync_snapshot(target)
                return result
            finally:
                for client in self.clients:
                    try:
                        client.drive.close()
                    except Exception:
                        print("Warning: Drive client transport cleanup failed.")

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
    parser.add_argument("--workers", type=int, default=None,
                        help=f"Parallel file uploads (default {DEFAULT_WORKERS}, maximum {MAX_WORKERS}); "
                             "also configurable with DRIVE_SYNC_WORKERS.")
    args = parser.parse_args()
    try:
        try:
            workers = args.workers if args.workers is not None else int(os.environ.get("DRIVE_SYNC_WORKERS", DEFAULT_WORKERS))
        except ValueError:
            raise SyncError(f"DRIVE_SYNC_WORKERS must be an integer between 1 and {MAX_WORKERS}.") from None
        if not 1 <= workers <= MAX_WORKERS:
            raise SyncError(f"Worker count must be between 1 and {MAX_WORKERS}.")
        head = git(ROOT, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        if STATE.resolve().is_relative_to(ROOT.resolve()):
            raise SyncError("Synchronization state must be outside the repository.")
        state = load_state(STATE, ROOT)
        print_preview(ROOT, state, head)
        if not args.sync:
            print("Preview only; no credentials loaded, state written, or API calls made.")
            return 0
        if not args.yes and input("Synchronize to Google Drive, including moving managed Git deletions to Trash? [y/N] ").lower() != "y":
            return 1
        Synchronizer(ROOT, STATE, drive_factory=build_drive, workers=workers).sync(head)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"Drive synchronization stopped: {safe_error(error)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
