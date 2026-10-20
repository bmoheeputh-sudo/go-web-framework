"""Offline integration tests: real temporary Git repositories, mocked Drive API."""

from collections import defaultdict, deque
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

import httplib2
from googleapiclient.errors import HttpError

from scripts import drive_sync as ds


def http_error(status):
    return HttpError(httplib2.Response({"status": str(status)}), b"sensitive response body")


class FakeRequest:
    def __init__(self, server, method, args):
        self.server, self.method, self.args = server, method, args
        self.headers = {}
        self.callbacks = []

    def add_response_callback(self, callback):
        self.callbacks.append(callback)

    def execute(self, num_retries=0):
        server = self.server
        uploading = self.method in {"create", "update"} and "media_body" in self.args
        with server.lock:
            key = (self.method, self.args.get("fileId") or self.args.get("body", {}).get("id"))
            name_key = (self.method, self.args.get("body", {}).get("name"))
            queue = server.faults[key] or server.faults[name_key] or server.faults[self.method]
            fault = queue.popleft() if queue else None
            server.events.append((self.method, copy.deepcopy(self.args.get("body", {})), threading.get_ident()))
            if uploading:
                server.active += 1
                server.max_active = max(server.max_active, server.active)
        try:
            if uploading and server.barrier:
                server.barrier.wait(timeout=5)
            if isinstance(fault, Exception):
                raise fault
            if callable(fault):
                fault(self)
            with server.lock:
                result = server.respond(self.method, self.args, self.headers)
            for callback in self.callbacks:
                callback({"etag": '"' + str(result.get("version", "1")) + '"'})
            if fault == "timeout_after":
                raise TimeoutError("response lost after remote operation")
            return result
        finally:
            if uploading:
                with server.lock:
                    server.active -= 1


class FakeDrive:
    """Independent client objects sharing a locked fake remote, never Google."""

    def __init__(self):
        self.items = {}
        self.next_id = 0
        self.faults = defaultdict(deque)
        self.lock = threading.RLock()
        self.active = self.max_active = 0
        self.barrier = None
        self.clients = []
        self.events = []
        self.api = MagicMock()  # Aggregate calls only; never passed as a client.
        self.files = self.api.files.return_value
        for method in ("list", "get", "generateIds", "create", "update"):
            getattr(self.files, method).side_effect = self.request_factory(method)

    def client(self):
        api = MagicMock()
        owner = threading.get_ident()
        for method in ("list", "get", "generateIds", "create", "update"):
            def dispatch(_method=method, **kwargs):
                if threading.get_ident() != owner:
                    raise AssertionError("Drive client used on another thread")
                self.api.files()
                return getattr(self.files, _method)(**kwargs)
            getattr(api.files.return_value, method).side_effect = dispatch
        with self.lock:
            self.clients.append(api)
        return api

    def request_factory(self, method):
        return lambda **kwargs: FakeRequest(self, method, kwargs)

    def respond(self, method, args, headers=None):
        if method == "list":
            values = re.findall(r"'((?:\\.|[^'\\])*)'", args["q"])
            name, parent = [re.sub(r"\\(.)", r"\1", value) for value in values]
            return {"files": [copy.deepcopy(item) for item in self.items.values()
                              if item["name"] == name and parent in item["parents"]
                              and not item.get("trashed")]}
        if method == "generateIds":
            self.next_id += 1
            return {"ids": [f"generated-{self.next_id}"]}
        if method == "get":
            if args["fileId"] == ds.FOLDER_ID:
                return dict(id=ds.FOLDER_ID, name="backup", parents=[], mimeType=ds.FOLDER_MIME,
                            trashed=False, explicitlyTrashed=False, version="1")
            if args["fileId"] not in self.items:
                raise http_error(404)
            return copy.deepcopy(self.items[args["fileId"]])
        if method == "create":
            body = args["body"]
            if body["id"] in self.items:
                raise http_error(409)
            item = {"mimeType": "text/plain", "trashed": False, "explicitlyTrashed": False,
                    "version": "0", **copy.deepcopy(body)}
            self.items[item["id"]] = item
        else:
            item = self.items[args["fileId"]]
            if headers.get("If-Match") != '"' + str(item["version"]) + '"':
                raise http_error(412)
            body = copy.deepcopy(args.get("body", {}))
            item.setdefault("appProperties", {}).update(body.pop("appProperties", {}))
            item.update(body)
            if "trashed" in body:
                item["explicitlyTrashed"] = body["trashed"]
            if "removeParents" in args:
                item["parents"] = [p for p in item["parents"]
                                   if p not in args["removeParents"].split(",")]
            if "addParents" in args:
                item["parents"].append(args["addParents"])
        if "media_body" in args:
            upload = args["media_body"]
            item["content"] = upload.getbytes(0, upload.size())
            item["md5Checksum"] = hashlib.md5(item["content"]).hexdigest()
            item["size"] = str(len(item["content"]))
        item["version"] = str(int(item["version"]) + 1)
        return copy.deepcopy(item)

    def add(self, name, parent=ds.FOLDER_ID, file_id=None, mime="text/plain", content=b"source\n"):
        file_id = file_id or f"existing-{len(self.items)}"
        self.items[file_id] = dict(id=file_id, name=name, mimeType=mime, parents=[parent],
                                   trashed=False, explicitlyTrashed=False, version="1",
                                   content=content, size=str(len(content)),
                                   md5Checksum=hashlib.md5(content).hexdigest())
        return file_id

class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.state = Path(self.temp.name) / "config/state.json"
        self.environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Backup Test")
        self.git("config", "user.email", "backup@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.hooksPath", str(Path(self.temp.name) / "no-hooks"))
        self.remote = FakeDrive()
        self.sleep = MagicMock()
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root,
                                       env=self.environment, stderr=subprocess.PIPE).decode().strip()

    def write(self, name, text="source\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git("add", "-f", "--all")
        self.git("commit", "-m", "test")
        return self.git("rev-parse", "HEAD")

    def synchronizer(self):
        return ds.Synchronizer(self.root, self.state, self.remote.client, self.sleep, workers=1)

    def sync(self, commit):
        return self.synchronizer().sync(commit)

    def read_state(self):
        return json.loads(self.state.read_text())

    def counts(self, **values):
        return dict(dict(created=0, updated=0, renamed=0, trashed=0, skipped=0,
                         blocked=0, failed=0), **values)

    def test_first_sync_existing_history_and_remote_file(self):
        self.write("old.py", "old\n")
        self.commit()
        self.write("src/new.py", "new\n")
        target = self.commit()
        existing_id = self.remote.add("old.py")
        counts = self.sync(target)
        self.assertEqual(counts, self.counts(created=1, updated=1))
        self.assertEqual(self.remote.items[existing_id]["content"], b"old\n")
        folder = next(i for i in self.remote.items.values() if i["name"] == "src")
        child = next(i for i in self.remote.items.values() if i["name"] == "new.py")
        self.assertEqual(child["parents"], [folder["id"]])
        self.assertEqual(self.read_state()["last_commit"], target)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)

    def test_incremental_update_addition_and_unchanged(self):
        self.write("a.py")
        self.write("unchanged.py")
        self.sync(self.commit())
        old_id = self.read_state()["resources"]["a.py"]["id"]
        self.remote.api.reset_mock()
        self.write("a.py", "updated\n")
        self.write("new.py")
        counts = self.sync(self.commit())
        self.assertEqual(counts, self.counts(created=1, updated=1, skipped=1))
        self.assertEqual(self.remote.files.update.call_args.kwargs["fileId"], old_id)
        self.assertEqual(self.remote.files.update.call_count, 1)
        self.assertEqual(self.remote.files.create.call_count, 1)

    def test_unchanged_commit_makes_no_drive_requests(self):
        self.write("a.py")
        target = self.commit()
        self.sync(target)
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(target)["skipped"], 1)
        self.remote.api.files.assert_not_called()

    def test_uploads_commit_snapshot_not_worktree_or_untracked_files(self):
        self.write("a.py", "committed\n")
        target = self.commit()
        self.write("a.py", "uncommitted\n")
        self.write("untracked.py")
        self.sync(target)
        self.assertEqual(len(self.remote.items), 1)
        self.assertEqual(next(iter(self.remote.items.values()))["content"], b"committed\n")

    def test_rename_moves_same_id_and_deletion_trashes_only_file(self):
        self.write("old.py")
        self.sync(self.commit())
        file_id = self.read_state()["resources"]["old.py"]["id"]
        (self.root / "nested").mkdir()
        self.git("mv", "old.py", "nested/new.py")
        self.assertEqual(self.sync(self.commit())["renamed"], 1)
        self.assertEqual(self.remote.items[file_id]["name"], "new.py")
        self.assertEqual(self.read_state()["resources"]["nested/new.py"]["id"], file_id)
        self.assertNotIn("old.py", self.read_state()["resources"])
        self.git("rm", "nested/new.py")
        self.assertEqual(self.sync(self.commit())["trashed"], 1)
        self.assertIn(file_id, self.remote.items)
        self.assertTrue(self.remote.items[file_id]["trashed"])
        self.assertFalse(any(i["trashed"] for i in self.remote.items.values() if i["mimeType"] == ds.FOLDER_MIME))
        self.remote.files.delete.assert_not_called()

    def test_timeout_after_create_does_not_duplicate(self):
        self.write("a.py")
        self.remote.faults["create"].append("timeout_after")
        counts = self.sync(self.commit())
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(self.remote.items), 1)
        self.assertEqual(self.remote.files.generateIds.call_count, 1)
        ids = [call.kwargs["body"]["id"] for call in self.remote.files.create.call_args_list]
        self.assertEqual(len(ids), 1)
        self.sleep.assert_not_called()

    def test_timeout_after_folder_create_does_not_duplicate(self):
        self.write("src/a.py")
        self.remote.faults["create"].append("timeout_after")
        self.sync(self.commit())
        self.assertEqual(len(self.remote.items), 2)
        self.assertEqual(sum(i["mimeType"] == ds.FOLDER_MIME for i in self.remote.items.values()), 1)

    def test_lost_create_response_recovers_across_executions(self):
        self.write("a.py")
        target = self.commit()
        self.remote.faults["create"].append("timeout_after")
        self.remote.faults[("get", "generated-1")].extend([None] + [TimeoutError()] * ds.ATTEMPTS)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertEqual(len(self.remote.items), 1)
        reserved_id = self.read_state()["resources"]["a.py"]["id"]
        self.remote.api.reset_mock()
        self.sync(target)
        self.assertEqual(list(self.remote.items), [reserved_id])
        self.remote.files.create.assert_not_called()
        self.assertEqual(self.read_state()["last_commit"], target)

    def test_transient_http_and_network_retry_backoff(self):
        self.write("a.py")
        self.remote.faults["list"].extend([TimeoutError(), http_error(429),
                                            http_error(500), http_error(503)])
        self.sync(self.commit())
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [1, 2, 4, 8])

    def test_retry_exhaustion_preserves_checkpoint_and_ids(self):
        self.write("a.py")
        target = self.commit()
        self.remote.faults["create"].extend([TimeoutError()] * ds.ATTEMPTS)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        state = self.read_state()
        self.assertIsNone(state["last_commit"])
        self.assertEqual(state["pending_commit"], target)
        reserved_id = state["resources"]["a.py"]["id"]
        self.sync(target)
        self.assertEqual(list(self.remote.items), [reserved_id])
        self.assertEqual(self.read_state()["last_commit"], target)

    def test_checkpoint_recovery_skips_completed_files(self):
        self.write("a.py")
        self.write("b.py")
        target = self.commit()
        self.remote.faults["create"].extend([None, http_error(403)])
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertIsNone(self.read_state()["last_commit"])
        self.remote.api.reset_mock()
        counts = self.sync(target)
        self.assertEqual(counts, self.counts(created=1, skipped=1))
        self.remote.files.update.assert_not_called()
        self.assertEqual(self.read_state()["last_commit"], target)
        self.assertIsNone(self.read_state()["pending_commit"])

    def test_failed_update_keeps_previous_checkpoint(self):
        self.write("a.py")
        base = self.commit()
        self.sync(base)
        self.write("a.py", "updated\n")
        target = self.commit()
        self.remote.faults["update"].extend([TimeoutError()] * ds.ATTEMPTS)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertEqual(self.read_state()["last_commit"], base)
        self.assertEqual(self.sync(target)["updated"], 1)
        self.assertEqual(self.read_state()["last_commit"], target)

    def test_duplicate_detection_including_paginated_results(self):
        self.write("a.py")
        target = self.commit()
        self.remote.files.list.side_effect = [
            MagicMock(execute=MagicMock(return_value={"files": [{"id": "1"}], "nextPageToken": "page2"})),
            MagicMock(execute=MagicMock(return_value={"files": [{"id": "2"}]})),
        ]
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertIn("Ambiguous", self.output.getvalue())
        self.assertEqual(self.remote.files.list.call_args.kwargs["pageToken"], "page2")
        self.remote.files.create.assert_not_called()
        self.remote.files.update.assert_not_called()

    def test_duplicate_folder_fails_without_upload(self):
        self.write("src/a.py")
        self.remote.add("src", mime=ds.FOLDER_MIME)
        self.remote.add("src", mime=ds.FOLDER_MIME)
        with self.assertRaises(ds.SyncError):
            self.sync(self.commit())
        self.remote.files.create.assert_not_called()

    def test_native_file_collision_is_not_overwritten(self):
        self.write("a.py")
        self.remote.add("a.py", mime="application/vnd.google-apps.document")
        with self.assertRaises(ds.SyncError):
            self.sync(self.commit())
        self.remote.files.update.assert_not_called()

    def test_security_exclusions_and_symlinks(self):
        blocked = [".env", ".env.example", "key.pem", "id_ed25519", "credentials.json",
                   "config/service_account.json", "venv/pkg.py", "node_modules/a.js",
                   "dist/bundle.js", "backend/bin/server", "program.exe", "data.sqlite",
                   "secret.json", ".aws/config"]
        for name in blocked:
            self.write(name)
        self.write("innocent.txt", "-----BEGIN RSA PRIVATE KEY-----\nsecret")
        self.write("unexpected.json", '{"private_key":"hidden","client_email":"hidden"}')
        (self.root / "executable").write_bytes(b"\x7fELFbinary")
        (self.root / "link.py").symlink_to("/etc/passwd")
        self.write("safe.py")
        counts = self.sync(self.commit())
        self.assertEqual(counts["created"], 1)
        self.assertEqual(counts["skipped"], len(blocked) + 4)
        self.assertEqual(next(iter(self.remote.items.values()))["name"], "safe.py")

    def test_backup_source_and_security_test_fixtures_are_not_excluded(self):
        for source in (ds.ROOT / "scripts/drive_sync.py", Path(__file__)):
            with self.subTest(source=source.name):
                self.assertFalse(ds.unsafe_content(source.read_bytes()))

    def test_worktree_symlink_ancestor_fails_safely(self):
        self.write("src/a.py")
        target = self.commit()
        shutil.rmtree(self.root / "src")
        (self.root / "src").symlink_to(Path(self.temp.name))
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.api.files.assert_not_called()

    def test_path_traversal_and_control_characters_rejected(self):
        for name in ("../a.py", "/tmp/a.py", "src/../../a.py", "a\\b.py", "a\nb.py", "a//b.py"):
            with self.subTest(name=name), self.assertRaises(ds.SyncError):
                ds.validate_path(self.root, name)

    def test_apostrophe_filename_is_escaped(self):
        self.write("it's.py")
        self.remote.add("it's.py")
        self.assertEqual(self.sync(self.commit())["updated"], 1)
        self.assertIn("it\\'s.py", self.remote.files.list.call_args.kwargs["q"])

    def test_rewritten_history_fails_without_api_calls(self):
        self.write("a.py")
        self.sync(self.commit())
        self.git("checkout", "--orphan", "replacement")
        self.write("b.py")
        target = self.commit()
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.api.files.assert_not_called()

    def test_invalid_state_not_silently_reset(self):
        self.state.parent.mkdir()
        self.state.write_text("broken json")
        with self.assertRaises(ds.SyncError):
            self.synchronizer()
        self.assertEqual(self.state.read_text(), "broken json")

    def test_preview_does_not_load_credentials_or_write_state(self):
        self.write("a.py")
        self.commit()
        with patch.object(ds, "ROOT", self.root), patch.object(ds, "STATE", self.state), \
                patch.object(ds, "build_drive") as build, patch("sys.argv", ["drive_sync.py"]):
            self.assertEqual(ds.main(), 0)
        build.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_main_recovers_pending_snapshot_before_new_head(self):
        self.write("a.py")
        pending = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(pending)
        self.write("a.py", "newer\n")
        head = self.commit()
        with patch.object(ds, "ROOT", self.root), patch.object(ds, "STATE", self.state), \
                patch.object(ds, "build_drive", side_effect=self.remote.client), \
                patch("sys.argv", ["drive_sync.py", "--sync", "--yes"]):
            self.assertEqual(ds.main(), 0)
        self.assertEqual(self.read_state()["last_commit"], head)
        self.assertEqual(next(iter(self.remote.items.values()))["content"], b"newer\n")

    def test_state_lock_rejects_concurrent_sync(self):
        with ds.state_lock(self.state):
            with self.assertRaises(ds.SyncError), ds.state_lock(self.state):
                pass

    def test_error_output_redacts_api_response(self):
        self.write("a.py")
        self.remote.faults["list"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(self.commit())
        self.assertNotIn("sensitive response body", self.output.getvalue())
        self.assertIn("HTTP 403", self.output.getvalue())
        self.assertEqual(self.remote.files.list.call_count, 1)

    def test_authentication_configuration_and_timeout(self):
        with patch("google.oauth2.service_account.Credentials.from_service_account_file") as credentials, \
                patch("google_auth_httplib2.AuthorizedHttp") as authorized, \
                patch("httplib2.Http") as http, patch("googleapiclient.discovery.build") as build:
            ds.build_drive()
        credentials.assert_called_once_with(str(ds.KEY), scopes=[ds.SCOPE], subject=ds.USER)
        http.assert_called_once_with(timeout=120)
        authorized.assert_called_once_with(credentials.return_value, http=http.return_value)
        build.assert_called_once_with("drive", "v3", http=authorized.return_value, cache_discovery=False)

    def test_five_concurrent_uploads_and_isolated_clients(self):
        for index in range(5):
            self.write(f"file-{index}.py")
        target = self.commit()
        self.remote.barrier = threading.Barrier(5)
        sync = ds.Synchronizer(self.root, self.state, self.remote.client, self.sleep)
        self.assertEqual(sync.workers, 5)
        self.assertEqual(sync.sync(target)["created"], 5)
        self.assertEqual(self.remote.max_active, 5)
        self.assertEqual(len(self.remote.clients), 6)  # Coordinator plus 5 isolated clients.
        self.assertEqual(len(self.read_state()["resources"]), 5)
        for client in self.remote.clients:
            client.close.assert_called_once()

    def test_worker_count_bounds_and_client_reuse_is_rejected(self):
        for count in (0, -1, 9):
            with self.assertRaises(ds.SyncError):
                ds.Synchronizer(self.root, self.state, self.remote.client, workers=count)
        self.assertEqual(ds.Synchronizer(self.root, self.state, self.remote.client, workers=8).workers, 8)
        self.write("a.py")
        shared = self.remote.client()
        with self.assertRaises(ds.SyncError):
            ds.Synchronizer(self.root, self.state, lambda: shared, self.sleep).sync(self.commit())
        self.remote.files.create.assert_not_called()

    def test_parallel_shared_parents_are_created_once_before_uploads(self):
        for index in range(5):
            self.write(f"src/shared/file-{index}.py")
        self.remote.barrier = threading.Barrier(5)
        ds.Synchronizer(self.root, self.state, self.remote.client, self.sleep).sync(self.commit())
        folders = [i for i in self.remote.items.values() if i["mimeType"] == ds.FOLDER_MIME]
        self.assertEqual(len(folders), 2)
        deepest = next(i for i in folders if i["name"] == "shared")
        self.assertEqual({i["parents"][0] for i in self.remote.items.values()
                          if i["mimeType"] != ds.FOLDER_MIME}, {deepest["id"]})
        creates = [body for method, body, _ in self.remote.events if method == "create"]
        self.assertEqual([i["name"] for i in creates[:2]], ["src", "shared"])

    def test_parallel_failure_retains_success_and_retry_does_not_duplicate(self):
        for index in range(5):
            self.write(f"file-{index}.py")
        target = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            ds.Synchronizer(self.root, self.state, self.remote.client, self.sleep).sync(target)
        state = self.read_state()
        self.assertIsNone(state["last_commit"])
        self.assertEqual(state["pending_commit"], target)
        completed = {r["id"] for r in state["resources"].values() if r.get("blob")}
        self.assertEqual(len(completed), 4)
        self.remote.api.reset_mock()
        counts = self.sync(target)
        self.assertEqual(counts["skipped"], 4)
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(self.remote.items), 5)
        self.assertEqual(self.remote.files.create.call_count, 1)
        self.remote.files.update.assert_not_called()
        self.assertTrue(completed.issubset(self.remote.items))

    def deleted_file(self, name="a.py"):
        self.write(name)
        self.sync(self.commit())
        record = self.read_state()["resources"][name]
        self.git("rm", name)
        return record, self.commit()

    def test_trash_requires_matching_creation_markers(self):
        record, target = self.deleted_file()
        self.remote.items[record["id"]]["appProperties"]["gwf_resource"] = "other"
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.files.update.assert_not_called()
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_approved_mirror_policy_can_trash_previously_adopted_file(self):
        self.write("a.py")
        existing = self.remote.add("a.py")
        self.sync(self.commit())
        self.assertEqual(self.read_state()["resources"]["a.py"]["origin"], "adopted")
        self.git("rm", "a.py")
        self.assertEqual(self.sync(self.commit())["trashed"], 1)
        self.assertTrue(self.remote.items[existing]["trashed"])
        self.assertNotIn("gwf_resource", self.remote.items[existing].get("appProperties", {}))

    def test_legacy_v1_record_is_verified_against_path_type_and_content(self):
        record, target = self.deleted_file("a.txt")
        state = self.read_state()
        state["version"] = 1
        state.pop("backup_id")
        state["resources"]["a.txt"] = {"id": record["id"], "blob": record["blob"]}
        ds.save_state(self.state, state)
        self.assertEqual(self.sync(target)["trashed"], 1)
        self.assertEqual(self.read_state()["version"], 2)
        self.assertEqual(self.read_state()["resources"]["a.txt"]["origin"], "adopted")

    def test_missing_or_incomplete_record_never_trashes_by_filename(self):
        record, target = self.deleted_file()
        for replacement in (None, {"id": record["id"]}):
            state = self.read_state()
            if replacement:
                state["resources"]["a.py"] = replacement
            else:
                state["resources"].pop("a.py", None)
            ds.save_state(self.state, state)
            self.remote.api.reset_mock()
            with self.assertRaises(ds.SyncError):
                self.sync(target)
            self.remote.files.update.assert_not_called()
            self.remote.files.list.assert_not_called()
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_external_rename_move_type_content_or_missing_id_blocks_trash(self):
        record, target = self.deleted_file()
        original = copy.deepcopy(self.remote.items[record["id"]])
        for change in ({"name": "other.py"}, {"parents": ["elsewhere"]},
                       {"mimeType": ds.FOLDER_MIME}, {"md5Checksum": "changed"}, None):
            with self.subTest(change=change):
                if change is None:
                    self.remote.items.pop(record["id"], None)
                    replacement = self.remote.add("a.py", file_id="replacement")
                else:
                    self.remote.items[record["id"]] = {**copy.deepcopy(original), **change}
                self.remote.api.reset_mock()
                with self.assertRaises(ds.SyncError):
                    self.sync(target)
                self.remote.files.update.assert_not_called()
                self.remote.files.list.assert_not_called()
                if change is None:
                    self.assertFalse(self.remote.items[replacement]["trashed"])

    def test_already_trashed_is_idempotent_only_after_verification(self):
        record, target = self.deleted_file()
        self.remote.items[record["id"]].update(trashed=True, explicitlyTrashed=True)
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(target)["trashed"], 1)
        self.remote.files.update.assert_not_called()
        self.assertTrue(self.read_state()["resources"]["a.py"]["trashed"])
        self.assertTrue(any(c.kwargs["fileId"] == record["id"] for c in self.remote.files.get.call_args_list))

    def test_timeout_after_trash_is_reconciled_without_second_mutation(self):
        record, target = self.deleted_file()
        self.remote.api.reset_mock()
        self.remote.faults["update"].append("timeout_after")
        self.assertEqual(self.sync(target)["trashed"], 1)
        self.assertEqual(self.remote.files.update.call_count, 1)
        self.assertTrue(self.remote.items[record["id"]]["trashed"])

    def test_ambiguous_trash_recovers_across_executions_without_retrash(self):
        record, target = self.deleted_file()
        self.remote.faults["update"].append("timeout_after")
        # Initial validation + pre-write GET succeed, reconciliation cannot read.
        self.remote.faults[("get", record["id"])].extend([None, None] + [TimeoutError()] * ds.ATTEMPTS)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertEqual(self.read_state()["pending_commit"], target)
        self.assertTrue(self.remote.items[record["id"]]["trashed"])
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(target)["trashed"], 1)
        self.remote.files.update.assert_not_called()

    def test_conditional_trash_detects_concurrent_remote_change(self):
        record, target = self.deleted_file()
        def change_before_write(request):
            item = self.remote.items[record["id"]]
            item["name"] = "external.py"
            item["version"] = str(int(item["version"]) + 1)
        self.remote.faults["update"].append(change_before_write)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_no_etag_means_no_unguarded_trash(self):
        record, target = self.deleted_file()
        original = ds.DriveClient.get
        def without_etag(client, file_id):
            item = original(client, file_id)
            if item:
                item.pop("_etag", None)
            return item
        self.remote.api.reset_mock()
        with patch.object(ds.DriveClient, "get", without_etag), self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.files.update.assert_not_called()
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_completed_deletion_does_not_trash_recreated_file(self):
        record, deletion = self.deleted_file()
        self.sync(deletion)
        self.write("a.py", "recreated\n")
        target = self.commit()
        self.sync(target)
        new = self.read_state()["resources"]["a.py"]
        self.assertNotEqual(new["id"], record["id"])
        self.assertTrue(self.remote.items[record["id"]]["trashed"])
        self.assertFalse(self.remote.items[new["id"]]["trashed"])
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(deletion)
        self.remote.api.files.assert_not_called()
        self.assertEqual(self.read_state()["last_commit"], target)

    def test_excluded_and_sensitive_deletions_are_not_trashed(self):
        names = [".env", "secret.json", "private.pem", "node_modules/a.js", "innocent.txt"]
        for name in names:
            self.write(name, "-----BEGIN RSA PRIVATE KEY-----\n" if name == "innocent.txt" else "private\n")
        self.write("safe.py")
        self.sync(self.commit())
        state = self.read_state()
        tree = ds.snapshot(self.root, state["last_commit"])
        for name in names:
            file_id = self.remote.add(name)
            state["resources"][name] = {"id": file_id, "blob": tree[name][2]}
            self.git("rm", name)
        ds.save_state(self.state, state)
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(self.commit())["skipped"], 6)
        self.remote.api.files.assert_not_called()
        self.assertFalse(any(i["trashed"] for i in self.remote.items.values()))

    def test_deleted_file_does_not_trash_externally_moved_parent(self):
        record, target = self.deleted_file("src/a.py")
        folder = self.read_state()["resources"]["src/"]["id"]
        self.remote.items[folder]["parents"] = ["elsewhere"]
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.files.update.assert_not_called()
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_interrupted_sync_preserves_completed_journal_entries(self):
        self.write("a.py")
        self.write("b.py")
        target = self.commit()
        original = ds.Synchronizer.upload
        def interrupted(sync, op, parent, commit):
            if op.name == "b.py":
                raise KeyboardInterrupt()
            return original(sync, op, parent, commit)
        with patch.object(ds.Synchronizer, "upload", interrupted), self.assertRaises(KeyboardInterrupt):
            self.sync(target)
        self.assertEqual(self.read_state()["pending_commit"], target)
        completed_id = self.read_state()["resources"]["a.py"]["id"]
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(target)["skipped"], 1)
        self.assertEqual(self.remote.files.create.call_count, 1)
        self.assertEqual(self.read_state()["resources"]["a.py"]["id"], completed_id)

    def test_real_process_lock_blocks_second_synchronizer(self):
        with ds.state_lock(self.state):
            code = """import sys
from pathlib import Path
from scripts.drive_sync import state_lock, SyncError
try:
    with state_lock(Path(sys.argv[1])):
        sys.exit(1)
except SyncError:
    sys.exit(23)
"""
            result = subprocess.run([sys.executable, "-c", code, str(self.state)],
                                    cwd=ds.ROOT, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 23, result.stderr)

    def test_pending_failure_must_finish_before_later_commit(self):
        self.write("a.py", "pending\n")
        pending = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(pending)
        self.write("a.py", "newer\n")
        head = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(head)
        self.assertEqual(self.read_state()["pending_commit"], pending)
        self.assertIsNone(self.read_state()["last_commit"])
        self.sync(head)
        self.assertEqual(next(iter(self.remote.items.values()))["content"], b"newer\n")
        self.assertEqual(self.read_state()["last_commit"], head)

    def test_many_concurrent_completions_leave_valid_atomic_state(self):
        for index in range(35):
            self.write(f"file-{index}.py", f"content {index}\n")
        target = self.commit()
        saved = []
        original = ds.save_state
        def verify_save(path, state):
            original(path, state)
            read = json.loads(path.read_text())
            self.assertEqual(read, state)
            saved.append(read)
        with patch.object(ds, "save_state", verify_save):
            ds.Synchronizer(self.root, self.state, self.remote.client, self.sleep).sync(target)
        state = self.read_state()
        self.assertEqual(len(state["resources"]), 35)
        self.assertTrue(all(r.get("blob") and not r.get("intent") for r in state["resources"].values()))
        self.assertEqual(len({r["id"] for r in state["resources"].values()}), 35)
        self.assertIsNone(state["pending_commit"])
        self.assertEqual(state["last_commit"], target)
        self.assertLessEqual(self.remote.max_active, ds.DEFAULT_WORKERS)
        self.assertGreater(len(saved), 70)

    def test_timed_out_update_is_confirmed_before_any_retry(self):
        self.write("a.py")
        self.sync(self.commit())
        self.write("a.py", "changed\n")
        target = self.commit()
        self.remote.api.reset_mock()
        self.remote.faults["update"].append("timeout_after")
        self.assertEqual(self.sync(target)["updated"], 1)
        self.assertEqual(self.remote.files.update.call_count, 1)
        self.remote.files.create.assert_not_called()
        self.assertEqual(next(iter(self.remote.items.values()))["content"], b"changed\n")

    def test_interrupted_rename_reuses_original_id_and_never_trashes(self):
        self.write("old.py")
        self.sync(self.commit())
        record = self.read_state()["resources"]["old.py"]
        self.git("mv", "old.py", "new.py")
        target = self.commit()
        self.remote.faults["update"].append("timeout_after")
        # Before intent + pre-write reads; then lose reconciliation responses.
        self.remote.faults[("get", record["id"])].extend([None, None] + [TimeoutError()] * ds.ATTEMPTS)
        with self.assertRaises(ds.SyncError):
            self.sync(target)
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(target)["renamed"], 1)
        self.remote.files.update.assert_not_called()
        self.assertNotIn("old.py", self.read_state()["resources"])
        self.assertEqual(self.read_state()["resources"]["new.py"]["id"], record["id"])
        self.assertEqual(len(self.remote.items), 1)
        self.assertFalse(self.remote.items[record["id"]]["trashed"])

    def test_rename_into_security_exclusion_retains_old_resource(self):
        self.write("old.py")
        self.sync(self.commit())
        file_id = self.read_state()["resources"]["old.py"]["id"]
        self.git("mv", "old.py", "secret.py")
        self.remote.api.reset_mock()
        self.assertEqual(self.sync(self.commit())["skipped"], 1)
        self.remote.api.files.assert_not_called()
        self.assertEqual(self.remote.items[file_id]["name"], "old.py")
        self.assertFalse(self.remote.items[file_id]["trashed"])

    def test_pending_history_must_be_ancestor_of_new_head_before_any_writes(self):
        self.write("a.py")
        pending = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(pending)
        before = self.state.read_bytes()
        self.git("checkout", "--orphan", "replacement")
        self.write("b.py")
        head = self.commit()
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(head)
        self.assertEqual(self.state.read_bytes(), before)
        self.remote.api.files.assert_not_called()

    def test_newer_resource_cannot_be_overwritten_by_older_pending_commit(self):
        self.write("a.py")
        pending = self.commit()
        self.remote.faults["create"].append(http_error(403))
        with self.assertRaises(ds.SyncError):
            self.sync(pending)
        self.write("a.py", "newer\n")
        head = self.commit()
        state = self.read_state()
        state["resources"]["a.py"]["commit"] = head
        ds.save_state(self.state, state)
        self.remote.api.reset_mock()
        with self.assertRaises(ds.SyncError):
            self.sync(head)
        self.remote.files.create.assert_not_called()
        self.remote.files.update.assert_not_called()
        self.assertEqual(self.read_state()["pending_commit"], pending)

    def test_reusing_synchronizer_allocates_fresh_clients_after_cleanup(self):
        self.write("a.py")
        sync = self.synchronizer()
        sync.sync(self.commit())
        old_clients = list(self.remote.clients)
        self.write("a.py", "changed\n")
        sync.sync(self.commit())
        self.assertGreater(len(self.remote.clients), len(old_clients))
        for client in self.remote.clients:
            client.close.assert_called_once()

    def test_preview_summary_and_worker_configuration_are_offline(self):
        self.write("a.py")
        self.commit()
        with patch.object(ds, "ROOT", self.root), patch.object(ds, "STATE", self.state), \
                patch.object(ds, "build_drive") as build, \
                patch.dict(os.environ, {"DRIVE_SYNC_WORKERS": "8"}), \
                patch("sys.argv", ["drive_sync.py"]):
            self.assertEqual(ds.main(), 0)
        build.assert_not_called()
        self.assertIn("create=1", self.output.getvalue())
        self.assertIn("trash=0", self.output.getvalue())
        self.assertIn("blocked=0", self.output.getvalue())
        self.assertFalse(self.state.exists())
        with patch.dict(os.environ, {"DRIVE_SYNC_WORKERS": "9"}), \
                patch("sys.argv", ["drive_sync.py"]):
            self.assertEqual(ds.main(), 1)


class BackupShellTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copy(ds.ROOT / "backup.sh", self.root / "backup.sh")
        (self.root / ".venv/bin").mkdir(parents=True)
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        self.log = self.root / "calls"
        self.environment = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}",
                            "TEST_CALLS": str(self.log), "TEST_STAGED": "1", "TEST_PUSH_EXIT": "0"}
        (fake_bin / "git").write_text('''#!/usr/bin/env bash
echo "git $*" >> "$TEST_CALLS"
case "$1 $2" in
  "branch --show-current") echo main ;;
  "remote get-url") echo git@github.com:example/repo.git ;;
  "diff --cached") [[ "$TEST_STAGED" != 1 ]] ;;
  "push origin") exit "$TEST_PUSH_EXIT" ;;
esac
''')
        (fake_bin / "git").chmod(0o755)
        (self.root / ".venv/bin/python").write_text('''#!/usr/bin/env bash
echo "python $*" >> "$TEST_CALLS"
exit 0
''')
        (self.root / ".venv/bin/python").chmod(0o755)

    def run_backup(self, answer="y\n"):
        result = subprocess.run(["bash", "backup.sh"], cwd=self.root, env=self.environment,
                                input=answer, text=True, capture_output=True)
        return result, self.log.read_text()

    def test_confirmation_commit_push_then_drive(self):
        result, log = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(log.index("git add -A"), log.index("git --no-pager diff"))
        self.assertLess(log.index("git commit"), log.index("git push origin main:main"))
        self.assertLess(log.index("git push"), log.index("python scripts/drive_sync.py --sync --yes"))

    def test_push_failure_stops_before_drive(self):
        self.environment["TEST_PUSH_EXIT"] = "1"
        result, log = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("python ", log)

    def test_no_empty_commit(self):
        self.environment["TEST_STAGED"] = "0"
        result, log = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("git commit", log)
        self.assertIn("git push", log)

    def test_rejection_prevents_commit_push_and_drive(self):
        for staged in ("0", "1"):
            self.log.write_text("")
            self.environment["TEST_STAGED"] = staged
            result, log = self.run_backup("n\n")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("git commit", log)
            self.assertNotIn("git push", log)
            self.assertNotIn("python ", log)


if __name__ == "__main__":
    unittest.main()
