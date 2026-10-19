"""Offline integration tests: real temporary Git repositories, mocked Drive API."""

from collections import defaultdict, deque
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import httplib2
from googleapiclient.errors import HttpError

from scripts import drive_sync as ds


def http_error(status):
    return HttpError(httplib2.Response({"status": str(status)}), b"sensitive response body")


class FakeDrive:
    """Google request mocks backed by an in-memory remote, including lost responses."""

    def __init__(self):
        self.items = {}
        self.next_id = 0
        self.faults = defaultdict(deque)
        self.api = MagicMock()
        self.files = self.api.files.return_value
        for method in ("list", "get", "generateIds", "create", "update"):
            getattr(self.files, method).side_effect = self.request_factory(method)

    def request_factory(self, method):
        def request(**kwargs):
            def execute(num_retries=0):
                fault = self.faults[method].popleft() if self.faults[method] else None
                if isinstance(fault, Exception):
                    raise fault
                result = self.respond(method, kwargs)
                if fault == "timeout_after":
                    raise TimeoutError("response lost after remote operation")
                return result
            return MagicMock(execute=MagicMock(side_effect=execute))
        return request

    def respond(self, method, args):
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
            if args["fileId"] not in self.items:
                raise http_error(404)
            return copy.deepcopy(self.items[args["fileId"]])
        if method == "create":
            body = args["body"]
            if body["id"] in self.items:
                raise http_error(409)
            item = {"mimeType": "text/plain", **copy.deepcopy(body)}
            self.items[item["id"]] = item
        else:
            item = self.items[args["fileId"]]
            item.update(args.get("body", {}))
            if "removeParents" in args:
                item["parents"] = [p for p in item["parents"]
                                   if p not in args["removeParents"].split(",")]
            if "addParents" in args:
                item["parents"].append(args["addParents"])
        if "media_body" in args:
            upload = args["media_body"]
            item["content"] = upload.getbytes(0, upload.size())
        return copy.deepcopy(item)

    def add(self, name, parent=ds.FOLDER_ID, file_id=None, mime="text/plain"):
        file_id = file_id or f"existing-{len(self.items)}"
        self.items[file_id] = {"id": file_id, "name": name, "mimeType": mime,
                               "parents": [parent]}
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
        return ds.Synchronizer(self.root, self.state, self.remote.api, self.sleep)

    def sync(self, commit):
        return self.synchronizer().sync(commit)

    def read_state(self):
        return json.loads(self.state.read_text())

    def test_first_sync_existing_history_and_remote_file(self):
        self.write("old.py", "old\n")
        self.commit()
        self.write("src/new.py", "new\n")
        target = self.commit()
        existing_id = self.remote.add("old.py")
        counts = self.sync(target)
        self.assertEqual(counts, dict(created=1, updated=1, skipped=0, failed=0))
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
        self.assertEqual(counts, dict(created=1, updated=1, skipped=1, failed=0))
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

    def test_rename_moves_same_id_and_deletion_retains_file(self):
        self.write("old.py")
        self.sync(self.commit())
        file_id = self.read_state()["resources"]["old.py"]["id"]
        (self.root / "nested").mkdir()
        self.git("mv", "old.py", "nested/new.py")
        self.assertEqual(self.sync(self.commit())["updated"], 1)
        self.assertEqual(self.remote.items[file_id]["name"], "new.py")
        self.assertEqual(self.read_state()["resources"]["nested/new.py"]["id"], file_id)
        self.assertNotIn("old.py", self.read_state()["resources"])
        self.git("rm", "nested/new.py")
        self.assertEqual(self.sync(self.commit())["skipped"], 1)
        self.assertIn(file_id, self.remote.items)
        self.remote.files.delete.assert_not_called()

    def test_timeout_after_create_does_not_duplicate(self):
        self.write("a.py")
        self.remote.faults["create"].append("timeout_after")
        counts = self.sync(self.commit())
        self.assertEqual(counts["created"], 1)
        self.assertEqual(len(self.remote.items), 1)
        self.assertEqual(self.remote.files.generateIds.call_count, 1)
        ids = [call.kwargs["body"]["id"] for call in self.remote.files.create.call_args_list]
        self.assertEqual(ids, [ids[0], ids[0]])
        self.sleep.assert_called_once_with(1)

    def test_timeout_after_folder_create_does_not_duplicate(self):
        self.write("src/a.py")
        self.remote.faults["create"].append("timeout_after")
        self.sync(self.commit())
        self.assertEqual(len(self.remote.items), 2)
        self.assertEqual(sum(i["mimeType"] == ds.FOLDER_MIME for i in self.remote.items.values()), 1)

    def test_lost_create_response_recovers_across_executions(self):
        self.write("a.py")
        target = self.commit()
        self.remote.faults["create"].extend(["timeout_after"] + [TimeoutError()] * (ds.ATTEMPTS - 1))
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
        self.assertEqual(counts, dict(created=1, updated=0, skipped=1, failed=0))
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
                patch.object(ds, "build_drive", return_value=self.remote.api), \
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
