"""Safety tests for tools/auto_update.py.

Every test builds its own throwaway source folder, git repository and local bare
"origin" in a temporary directory, copies the script into that repository and runs it
there. Nothing here writes to this checkout (one test copies its files into a scratch
folder to gate them), and no test talks to the network: git is limited to local paths
with GIT_ALLOW_PROTOCOL=file.

Sample private data (share links, home paths, e-mail addresses) is assembled at run
time, so this file itself passes the privacy gate it tests.
"""

import codecs
import contextlib
import importlib.util
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO = Path(__file__).resolve().parent
SCRIPT = REPO / "tools" / "auto_update.py"
FAKE_USER = "kitfake" + "user"  # assembled, so a gate run as this account finds nothing here
NOREPLY = "12345+" + "kit-tester" + "@users.noreply.github.com"
AUTO_SUBJECT = "auto-update: 2026-01-05"
TEST_KIT = (
    "import unittest\n\nimport kit\n\n\n"
    "class KitTests(unittest.TestCase):\n"
    "    def test_kit_is_ok(self):\n"
    "        self.assertTrue(kit.OK)\n"
)
KIT_FILES = {
    "kit.py": "OK = True\n",
    "test_kit.py": TEST_KIT,
    "mobile/rules.json": '{"rules": []}\n',
}


def link(scheme, rest):
    """Build "<scheme>://<rest>" without writing a scheme and "://" side by side in this file."""
    return scheme + ":" + "//" + rest


def skip_reason():
    if not SCRIPT.is_file():
        return "tools/auto_update.py is excluded from release archive"
    if shutil.which("git") is None:
        return "git is not installed"
    return None


def isolated_env(home):
    """Environment for git and the script: fake home, no user or system git config, local paths only."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "USERNAME": home.name,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_TERMINAL_PROMPT": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    env.pop("PRIVACY_KIT_SOURCE", None)
    env.pop("PRIVACY_KIT_OUTPUTS", None)
    return env


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)


def load_script(path, name):
    """Import a copy of the script, so its REPO is the folder above that copy's tools/."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def can_symlink(folder):
    try:
        os.symlink("target", folder / "link-probe")
    except (OSError, NotImplementedError):
        return False
    os.unlink(folder / "link-probe")
    return True


# A test, copied in from the source directory, that writes into the repository while the
# unit tests run and then fails, so the run rolls back with those files in place.
LATE_WRITER_TEST = (
    "import pathlib\nimport unittest\n\n\n"
    "class LateWriterTests(unittest.TestCase):\n"
    "    def test_writes_then_fails(self):\n"
    "        root = pathlib.Path(__file__).resolve().parent\n"
    "        (root / 'later 笔记.md').write_text('mine\\n', encoding='utf-8')\n"
    "        (root / 'mobile' / 'later.json').write_text('{}\\n', encoding='utf-8')\n"
    "        (root / 'extra' / 'later.txt').write_text('mine\\n', encoding='utf-8')\n"
    "        (root / 'kit.py.orig').write_text('mine\\n', encoding='utf-8')\n"
    "        with open(root / 'run.log', 'a', encoding='utf-8') as log:\n"
    "            log.write('appended during the run\\n')\n"
    "        self.fail('fixture')\n"
)


class Sandbox:
    """A source folder, a repository with the script in tools/, and a bare origin."""

    def __init__(self, root, initial_subject=AUTO_SUBJECT):
        self.root = root
        self.home = root / FAKE_USER
        self.source = root / "source"
        self.repo = root / "repo"
        self.origin = root / "origin.git"
        self.outputs = root / "outputs"
        write(self.home / ".gitconfig", "")
        self.env = isolated_env(self.home)
        for name, text in KIT_FILES.items():
            write(self.repo / name, text)
            write(self.source / name, text)
        write(self.repo / "README.md", "# Kit\n")
        write(self.source / "README.md", "# Kit\n")
        write(self.repo / "docs" / "guide.md", "Maintained in the repository.\n")
        shutil.copy2(REPO / ".gitignore", self.repo / ".gitignore")
        if (REPO / ".gitattributes").is_file():
            shutil.copy2(REPO / ".gitattributes", self.repo / ".gitattributes")
        write(self.repo / "tools" / "auto_update.py", SCRIPT.read_bytes())
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        for key, value in (("user.name", "Kit Tester"), ("user.email", NOREPLY),
                           ("commit.gpgsign", "false"), ("core.autocrlf", "false")):
            self.git("config", key, value)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", initial_subject)
        self.git("init", "-q", "--bare", str(self.origin), cwd=root)
        self.git("remote", "add", "origin", str(self.origin))
        self.git("push", "-q", "-u", "origin", "main")

    def git(self, *args, cwd=None, check=True):
        result = subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env,
                                capture_output=True, text=True, encoding="utf-8", errors="replace")
        if check and result.returncode:
            raise AssertionError(f"git {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result.stdout.strip()

    def commit_by_hand(self, name, text, subject="Edit by hand"):
        write(self.repo / name, text)
        self.git("add", "--", name)
        self.git("commit", "-q", "-m", subject)

    def update(self, *args, source=None):
        command = [sys.executable, "-B", str(self.repo / "tools" / "auto_update.py"),
                   "--source", str(source or self.source), "--outputs", str(self.outputs), *args]
        result = subprocess.run(command, cwd=self.repo, env=self.env, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=300)
        return result.returncode, result.stdout + result.stderr

    def head(self):
        return self.git("rev-parse", "HEAD")

    def origin_main(self):
        return self.git("--git-dir", str(self.origin), "rev-parse", "refs/heads/main", cwd=self.root)

    def status(self):
        return self.git("status", "--porcelain")

    def read(self, name):
        return (self.repo / name).read_text(encoding="utf-8")


class SandboxTestCase(unittest.TestCase):
    initial_subject = AUTO_SUBJECT

    def setUp(self):
        reason = skip_reason()
        if reason:
            self.skipTest(reason)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.box = Sandbox(Path(tmp.name), self.initial_subject)


class WorkingTreeSafetyTests(SandboxTestCase):
    def test_dirty_working_tree_is_refused_and_left_alone(self):
        box = self.box
        write(box.repo / "README.md", "# Kit\n\nHalf-written paragraph.\n")
        write(box.repo / "drafts" / "release-notes.md", "Draft.\n")
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        head, origin = box.head(), box.origin_main()
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn("uncommitted changes", output)
        self.assertIn("README.md", output)
        self.assertIn("drafts/", output)
        self.assertEqual(box.read("README.md"), "# Kit\n\nHalf-written paragraph.\n")
        self.assertEqual(box.read("drafts/release-notes.md"), "Draft.\n")
        self.assertEqual(box.read("kit.py"), "OK = True\n")
        self.assertEqual((box.head(), box.origin_main()), (head, origin))

    def test_failed_tests_put_back_only_the_synced_files(self):
        box = self.box
        write(box.repo / "run.log", "local log\n")
        write(box.repo / "old-release.zip", b"PK local")
        write(box.source / "kit.py", "OK = False\n")
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 1, output)
        self.assertIn("unit tests failed", output)
        self.assertEqual(box.read("kit.py"), "OK = True\n")
        self.assertEqual(box.read("run.log"), "local log\n")
        self.assertEqual((box.repo / "old-release.zip").read_bytes(), b"PK local")
        self.assertEqual(box.head(), head)
        self.assertEqual(box.status(), "")

    def test_rollback_restores_replaced_and_removed_files_and_drops_new_ones(self):
        box = self.box
        write(box.repo / "run.log", "local log\n")
        write(box.source / "kit.py", "OK = False\n")
        (box.source / "mobile" / "rules.json").unlink()
        write(box.source / "extra" / "helper.py", "HELPER = 1\n")
        head = box.head()
        code, output = box.update("--allow-new", "extra/helper.py")
        self.assertEqual(code, 1, output)
        self.assertIn("rollback:", output)
        self.assertEqual(box.read("kit.py"), "OK = True\n")
        self.assertEqual(box.read("mobile/rules.json"), KIT_FILES["mobile/rules.json"])
        self.assertFalse((box.repo / "extra").exists())
        self.assertEqual(box.read("run.log"), "local log\n")
        self.assertEqual(box.head(), head)
        self.assertEqual(box.status(), "")

    def test_failure_after_the_commit_keeps_the_commit(self):
        box = self.box
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        box.git("remote", "set-url", "origin", str(box.root / "missing-origin.git"))
        head = box.head()
        code, output = box.update("--push")
        self.assertEqual(code, 3, output)
        self.assertIn("local commits stay in the repository", output)
        self.assertNotEqual(box.head(), head)
        self.assertEqual(box.read("kit.py"), "OK = True\nVERSION = 2\n")
        self.assertEqual(box.status(), "")

    def test_no_sync_failure_does_not_roll_anything_back(self):
        box = self.box
        box.commit_by_hand("kit.py", "OK = False\n", subject=AUTO_SUBJECT)
        write(box.repo / "run.log", "local log\n")
        head = box.head()
        code, output = box.update("--no-sync")
        self.assertEqual(code, 1, output)
        self.assertNotIn("rollback:", output)
        self.assertEqual(box.read("kit.py"), "OK = False\n")
        self.assertEqual(box.read("run.log"), "local log\n")
        self.assertEqual(box.head(), head)

    def test_missing_source_is_refused_before_anything_changes(self):
        box = self.box
        write(box.repo / "run.log", "local log\n")
        head = box.head()
        code, output = box.update(source=box.root / "no-such-source")
        self.assertEqual(code, 2, output)
        self.assertIn("Kit source not found", output)
        self.assertNotIn("rollback:", output)
        self.assertEqual(box.read("run.log"), "local log\n")
        self.assertEqual(box.head(), head)
        self.assertEqual(box.status(), "")

    def test_allow_new_rejects_paths_outside_the_repository(self):
        code, output = self.box.update("--allow-new", "../outside.py")
        self.assertEqual(code, 2, output)
        self.assertIn("relative to the repository root", output)

    def test_files_that_appear_during_the_run_survive_the_rollback(self):
        box = self.box
        write(box.repo / "run.log", "local log\n")
        write(box.source / "test_late.py", LATE_WRITER_TEST)
        write(box.source / "extra" / "helper.py", "HELPER = 1\n")
        head = box.head()
        code, output = box.update("--allow-new", "test_late.py", "--allow-new", "extra/helper.py")
        self.assertEqual(code, 1, output)
        self.assertIn("removed 2 of 2 new file(s)", output)
        for name in ("later 笔记.md", "mobile/later.json", "extra/later.txt", "kit.py.orig"):
            self.assertEqual(box.read(name), "mine\n" if not name.endswith(".json") else "{}\n", name)
        self.assertEqual(box.read("run.log"), "local log\nappended during the run\n")
        self.assertFalse((box.repo / "test_late.py").exists())
        self.assertFalse((box.repo / "extra" / "helper.py").exists())
        self.assertEqual(box.head(), head)

    def test_untracked_file_hidden_by_configuration_stops_the_run(self):
        box = self.box
        box.git("config", "status.showUntrackedFiles", "no")
        write(box.repo / "extra.py", "MY OWN UNCOMMITTED WORK\n")
        write(box.source / "extra.py", "EXTRA = 1\n")
        head = box.head()
        code, output = box.update("--allow-new", "extra.py")
        self.assertEqual(code, 2, output)
        self.assertIn("uncommitted changes", output)
        self.assertIn("extra.py", output)
        self.assertEqual(box.read("extra.py"), "MY OWN UNCOMMITTED WORK\n")
        self.assertEqual(box.head(), head)

    def assert_hidden_edit_is_refused(self, flag, label):
        box = self.box
        box.git("update-index", flag, "mobile/rules.json")
        write(box.repo / "mobile" / "rules.json", '{"rules": ["local edit"]}\n')
        write(box.source / "mobile" / "rules.json", '{"rules": ["v2 from source"]}\n')
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn(f"mobile/rules.json  ({label})", output)
        self.assertEqual(box.read("mobile/rules.json"), '{"rules": ["local edit"]}\n')
        self.assertEqual(box.head(), head)

    def test_skip_worktree_entry_stops_the_run(self):
        self.assert_hidden_edit_is_refused("--skip-worktree", "skip-worktree")

    def test_assume_unchanged_entry_stops_the_run(self):
        self.assert_hidden_edit_is_refused("--assume-unchanged", "assume-unchanged")

    def test_tracked_symbolic_link_is_not_written_through(self):
        box = self.box
        if not can_symlink(box.root):
            self.skipTest("symbolic links are not available")
        outside = box.root / "outside-precious.txt"
        write(outside, "precious\n")
        os.symlink(outside, box.repo / "mobile" / "linked.json")
        box.git("add", "mobile/linked.json")
        box.git("commit", "-q", "-m", AUTO_SUBJECT)
        write(box.source / "mobile" / "linked.json", '{"from": "source"}\n')
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn("mobile/linked.json  (a symbolic link", output)
        self.assertEqual(outside.read_text(encoding="utf-8"), "precious\n")
        self.assertTrue(os.path.islink(box.repo / "mobile" / "linked.json"))
        self.assertEqual(box.head(), head)

    def test_ignored_files_are_summarised_by_folder(self):
        box = self.box
        for number in range(30):
            write(box.source / ".venv" / "lib" / f"m{number}.py", "X = 1\n")
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        code, output = box.update()
        self.assertEqual(code, 0, output)
        self.assertIn("sync:   skipped: .venv/ (30 files)", output)
        self.assertNotIn("m0.py", output)


class InProcessTests(SandboxTestCase):
    """Run parts of the script inside this process, with the sandbox's environment."""

    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, self.box.env, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.mod = load_script(self.box.repo / "tools" / "auto_update.py", "auto_update_in_process")

    def test_interrupt_right_after_the_commit_keeps_the_commit(self):
        box = self.box
        write(box.source / "new.py", "NEW = 1\n")
        head = box.head()
        log = io.StringIO()
        with mock.patch.object(self.mod, "non_noreply_emails", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(log):
            code = self.mod.main(["--source", str(box.source), "--outputs", str(box.outputs),
                                  "--allow-new", "new.py"])
        self.assertEqual(code, 3, log.getvalue())
        self.assertNotIn("rollback:", log.getvalue())
        self.assertNotEqual(box.head(), head)
        self.assertEqual(box.read("new.py"), "NEW = 1\n")
        self.assertEqual(box.status(), "")

    def test_plan_refuses_files_git_status_does_not_show(self):
        box = self.box
        write(box.repo / "extra.py", "MY OWN UNCOMMITTED WORK\n")
        write(box.source / "extra.py", "EXTRA = 1\n")
        box.git("update-index", "--assume-unchanged", "kit.py")
        write(box.repo / "kit.py", "OK = True  # local edit\n")
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(self.mod.Refused) as caught:
                self.mod.plan_sync(box.source, ["extra.py"])
        message = str(caught.exception)
        self.assertIn("extra.py  (already in the working tree", message)
        self.assertIn("kit.py  (the working tree copy differs from the last commit)", message)
        self.assertEqual(box.read("extra.py"), "MY OWN UNCOMMITTED WORK\n")
        self.assertEqual(box.read("kit.py"), "OK = True  # local edit\n")

    def test_git_refusal_reason_is_shown_instead_of_not_a_working_tree(self):
        # Git for Windows refuses a repository owned by another account (for example one cloned
        # in an elevated window) unless it is listed in safe.directory; its message says how.
        refusal = subprocess.CompletedProcess(
            ["git"], 128, "",
            "fatal: detected dubious ownership in repository at 'C:/kit'\n"
            "To add an exception for this directory, call:\n\n"
            "\tgit config --global --add safe.directory C:/kit\n")
        args = self.mod.build_parser().parse_args([])
        with mock.patch.object(self.mod, "git", return_value=refusal):
            with self.assertRaises(self.mod.Refused) as caught:
                self.mod.preflight(args)
        message = str(caught.exception)
        self.assertIn("detected dubious ownership", message)
        self.assertIn("git config --global --add safe.directory C:/kit", message)
        self.assertNotIn("is not a git working tree", message)
        outside = subprocess.CompletedProcess(["git"], 0, "false\n", "")
        with mock.patch.object(self.mod, "git", return_value=outside):
            with self.assertRaises(self.mod.Refused) as caught:
                self.mod.preflight(args)
        self.assertIn("is not a git working tree", str(caught.exception))

    def test_python_output_encoding_follows_pythonioencoding_then_the_locale(self):
        with mock.patch.dict(os.environ, {"PYTHONIOENCODING": "cp950:backslashreplace"}):
            self.assertEqual(self.mod.python_output_encoding(), "cp950")
        with mock.patch.dict(os.environ, {"PYTHONIOENCODING": ""}), \
                mock.patch.object(self.mod.locale, "getpreferredencoding", return_value="cp936"):
            self.assertEqual(self.mod.python_output_encoding(), "cp936")

    def test_windows_directory_junction_counts_as_a_linked_folder(self):
        # os.path.islink() is False for a junction (mklink /J); os.lstat() reports its reparse tag.
        box = self.box
        write(box.source / "mobile" / "rules.json", '{"rules": [1]}\n')
        # The script's REPO is resolved; on Windows runners the temporary folder is an 8.3 short
        # name (RUNNER~1), so compare with the path the script itself builds.
        junction = self.mod.REPO / "mobile"
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            if isinstance(path, (str, os.PathLike)) and Path(path) == junction:
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755,
                                       st_reparse_tag=self.mod.IO_REPARSE_TAG_MOUNT_POINT)
            return real_lstat(path, *args, **kwargs)

        with mock.patch.object(self.mod.os, "lstat", side_effect=lstat), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(self.mod.Refused) as caught:
                self.mod.plan_sync(box.source)
        self.assertIn("mobile/rules.json  (a symbolic link or directory junction", str(caught.exception))
        self.assertEqual(box.read("mobile/rules.json"), '{"rules": []}\n')

    def test_rollback_counts_only_what_it_put_back(self):
        touched = self.mod.Touched()
        touched.restore.append(Path("never-tracked.txt"))
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            self.mod.undo_sync(touched)
        self.assertIn("restored 0 of 1 tracked file(s)", log.getvalue())
        self.assertIn("rollback: PROBLEM", log.getvalue())


class ChildProcessOutputTests(SandboxTestCase):
    def test_failing_test_output_is_read_in_the_encoding_python_writes_to_a_pipe(self):
        # Python writes piped output in the locale encoding (cp950 on Traditional Chinese
        # Windows); PYTHONIOENCODING stands in for that locale here on every platform.
        box = self.box
        box.commit_by_hand("test_zz_probe.py", (
            "import unittest\n\n\n"
            "class ProbeTests(unittest.TestCase):\n"
            "    def test_probe(self):\n"
            "        self.assertEqual('設定檔', '設定')\n"
        ))
        box.env["PYTHONIOENCODING"] = "cp950"
        code, output = box.update("--no-sync")
        self.assertEqual(code, 1, output)
        self.assertIn("unit tests failed", output)
        self.assertIn("'設定檔' != '設定'", output)


class CaseOnlyRenameTests(SandboxTestCase):
    def test_a_name_that_differs_only_in_letter_case_stops_the_sync(self):
        box = self.box
        os.rename(box.source / "kit.py", box.source / "Kit.py")
        write(box.source / "Kit.py", "OK = True\nVERSION = 2\n")
        head = box.head()
        for extra in ((), ("--allow-new", "Kit.py")):
            with self.subTest(extra=extra):
                code, output = box.update(*extra)
                self.assertEqual(code, 2, output)
                self.assertIn("only in letter case", output)
                self.assertIn("Kit.py  (tracked as kit.py)", output)
                self.assertNotIn("would be deleted", output)
                self.assertNotIn("already in the working tree", output)
                self.assertEqual(box.head(), head)
                self.assertEqual(box.read("kit.py"), "OK = True\n")
                self.assertEqual(box.status(), "")


class HandEditTests(SandboxTestCase):
    def test_hand_edited_file_is_not_overwritten_or_deleted(self):
        box = self.box
        box.commit_by_hand("kit.py", "OK = True  # fixed in the repository\n")
        box.commit_by_hand("mobile/extra.json", "{}\n")
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn("changed by hand", output)
        self.assertIn("kit.py  (would be overwritten)", output)
        self.assertIn("mobile/extra.json  (would be deleted)", output)
        self.assertIn("--source-wins", output)
        self.assertEqual(box.read("kit.py"), "OK = True  # fixed in the repository\n")
        self.assertTrue((box.repo / "mobile" / "extra.json").is_file())
        self.assertEqual(box.head(), head)

    def test_source_wins_lets_the_source_overwrite(self):
        box = self.box
        box.commit_by_hand("kit.py", "OK = True  # fixed in the repository\n")
        code, output = box.update("--source-wins")
        self.assertEqual(code, 0, output)
        self.assertEqual(box.read("kit.py"), "OK = True\n")
        self.assertTrue(box.git("log", "-1", "--format=%s").startswith("auto-update: "))

    def test_files_changed_in_the_source_after_an_automatic_sync_are_synced(self):
        box = self.box
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        code, output = box.update()
        self.assertEqual(code, 0, output)
        self.assertEqual(box.read("kit.py"), "OK = True\nVERSION = 2\n")


class FreshlyPublishedRepositoryTests(SandboxTestCase):
    """Right after publishing, every commit was made by hand."""

    initial_subject = "Initial public release"

    def test_identical_files_are_not_conflicts(self):
        box = self.box
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 0, output)
        self.assertIn("nothing to commit", output)
        self.assertEqual(box.head(), head)

    def test_only_files_that_differ_from_head_are_conflicts(self):
        box = self.box
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn("kit.py  (would be overwritten)", output)
        self.assertNotIn("test_kit.py", output)
        self.assertNotIn("rules.json", output)
        self.assertEqual(box.read("kit.py"), "OK = True\n")


class NewFileTests(SandboxTestCase):
    def test_new_files_stop_the_run_until_each_is_named(self):
        box = self.box
        write(box.source / "extra.py", "EXTRA = 1\n")
        write(box.source / "mobile" / "extra.json", "{}\n")
        head = box.head()
        code, output = box.update()
        self.assertEqual(code, 2, output)
        self.assertIn("New files", output)
        self.assertIn("extra.py", output)
        self.assertIn("mobile/extra.json", output)
        self.assertFalse((box.repo / "extra.py").exists())
        code, output = box.update("--allow-new", "extra.py")
        self.assertEqual(code, 2, output)
        self.assertIn("mobile/extra.json", output)
        self.assertFalse((box.repo / "extra.py").exists())
        self.assertEqual(box.head(), head)
        code, output = box.update("--allow-new", "extra.py", "--allow-new", "mobile/extra.json")
        self.assertEqual(code, 0, output)
        committed = box.git("show", "--name-only", "--format=", "HEAD").splitlines()
        self.assertEqual(sorted(committed), ["extra.py", "mobile/extra.json"])

    def test_named_new_file_still_goes_through_the_privacy_gate(self):
        box = self.box
        write(box.source / "notes.md", "node: " + link("vless", "0123456789abcdef@host.example.com:443") + "\n")
        head = box.head()
        code, output = box.update("--allow-new", "notes.md")
        self.assertEqual(code, 1, output)
        self.assertIn("privacy gate blocked", output)
        self.assertFalse((box.repo / "notes.md").exists())
        self.assertEqual(box.head(), head)
        self.assertEqual(box.status(), "")

    def test_allow_new_cannot_let_in_ignored_or_local_output(self):
        box = self.box
        write(box.source / "notes.log", "local log\n")
        write(box.source / "env-health.html", "<html></html>\n")
        for name, reason in (("notes.log", ".gitignore ignores this path"), ("env-health.html", "never synced")):
            with self.subTest(name=name):
                code, output = box.update("--allow-new", name)
                self.assertEqual(code, 2, output)
                self.assertIn(reason, output)
                self.assertFalse((box.repo / name).exists())

    def test_local_tool_output_is_never_copied(self):
        box = self.box
        local_output = [
            "env-health.html", "mobile/env-health.html", "evidence/routes.json", "evidence/dns.txt",
            "CPPEK-LanDnsGuard-before-20260105.wfw", "CPPEK-KillSwitch-20260105.jsonl",
            "notes/scratch.bak", ".DS_Store", ".vscode/settings.json", ".venv/pyvenv.cfg", ".env",
            "guiConfigs/guiNConfig.json", "sources/article.md", "research-reports/a.md",
        ]
        for name in local_output:
            write(box.source / name, "local only\n")
        write(box.source / "kit.py", "OK = True\nVERSION = 2\n")
        code, output = box.update()
        self.assertEqual(code, 0, output)
        for name in local_output:
            self.assertFalse((box.repo / name).exists(), name)
        committed = box.git("show", "--name-only", "--format=", "HEAD").splitlines()
        self.assertEqual(committed, ["kit.py"])

    def test_gitignore_keeps_local_output_out_and_kit_files_in(self):
        box = self.box
        ignored = ["env-health.html", "report.html", "mobile/env-health.html", "evidence/routes.json",
                   "a.wfw", "logs/a.jsonl", ".env", ".venv/x", ".vscode/x", ".claude/x", ".DS_Store",
                   "x.bak", "guiConfigs/x", "guiNConfig.json", "sources/x.md", "docs/research-reports/x.md",
                   "THIRD-PARTY-NOTICE.md"]
        kept = ["README.md", "docs/index.html", "kit.py", "test_kit.py", "mobile/rules.json",
                "routing-template.json", "claude-doh-domains.txt", "Manage-WindowsKillSwitch.ps1"]
        # NUL-separated like tools/auto_update.py: text-mode pipes on Windows turn "\n" into "\r\n".
        result = subprocess.run(["git", "check-ignore", "--no-index", "-z", "--stdin"], cwd=box.repo, env=box.env,
                                input="\0".join(ignored + kept) + "\0", capture_output=True, text=True,
                                encoding="utf-8")
        self.assertEqual(sorted(name for name in result.stdout.split("\0") if name), sorted(ignored))


class PushTests(SandboxTestCase):
    def setUp(self):
        super().setUp()
        write(self.box.source / "kit.py", "OK = True\nVERSION = 2\n")

    def test_default_run_commits_locally_and_does_not_push(self):
        box = self.box
        origin, head = box.origin_main(), box.head()
        code, output = box.update()
        self.assertEqual(code, 0, output)
        self.assertNotEqual(box.head(), head)
        self.assertEqual(box.origin_main(), origin)
        self.assertIn("git show --stat", output)
        self.assertIn("--push", output)
        self.assertIn("kit.py", output)

    def test_push_flag_pushes_main(self):
        box = self.box
        code, output = box.update("--push")
        self.assertEqual(code, 0, output)
        self.assertEqual(box.origin_main(), box.head())

    def test_no_push_is_still_accepted(self):
        box = self.box
        origin = box.origin_main()
        code, output = box.update("--no-push")
        self.assertEqual(code, 0, output)
        self.assertEqual(box.origin_main(), origin)

    def test_push_and_no_push_together_are_an_error(self):
        box = self.box
        head = box.head()
        code, output = box.update("--push", "--no-push")
        self.assertEqual(code, 2, output)
        self.assertIn("not allowed with", output)
        self.assertEqual(box.head(), head)
        self.assertEqual(box.read("kit.py"), "OK = True\n")

    def test_push_is_refused_off_main(self):
        box = self.box
        box.git("checkout", "-q", "-b", "feature")
        head, origin = box.head(), box.origin_main()
        code, output = box.update("--push")
        self.assertEqual(code, 2, output)
        self.assertIn("feature", output)
        self.assertEqual((box.head(), box.origin_main()), (head, origin))
        self.assertEqual(box.read("kit.py"), "OK = True\n")
        branches = box.git("--git-dir", str(box.origin), "branch", "--list", cwd=box.root)
        self.assertNotIn("feature", branches)

    def test_push_is_refused_for_a_commit_with_a_non_noreply_address(self):
        box = self.box
        box.git("config", "user.email", "kit.tester" + "@mail.example.com")
        origin = box.origin_main()
        code, output = box.update("--push")
        self.assertEqual(code, 3, output)
        self.assertIn("not pushing", output)
        self.assertEqual(box.origin_main(), origin)

    def test_package_holds_committed_files_only(self):
        box = self.box
        write(box.repo / "run.log", "local log\n")
        code, output = box.update("--no-sync", "--force-package")
        self.assertEqual(code, 0, output)
        archives = list(box.outputs.glob("*.zip"))
        self.assertEqual(len(archives), 1, output)
        with zipfile.ZipFile(archives[0]) as archive:
            names = [name.split("/", 1)[1] for name in archive.namelist() if not name.endswith("/")]
        self.assertIn("kit.py", names)
        self.assertNotIn("run.log", names)
        self.assertFalse(any(name.startswith("tools/") for name in names), names)
        self.assertEqual(list(box.outputs.glob("*.part")), [])


class PrivacyGateTests(unittest.TestCase):
    """Run privacy_gate() in a scratch repository with a fixed, made-up identity."""

    def setUp(self):
        reason = skip_reason()
        if reason:
            self.skipTest(reason)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.home = root / FAKE_USER
        write(self.home / ".gitconfig", "")
        self.repo = root / "repo"
        write(self.repo / "tools" / "auto_update.py", SCRIPT.read_bytes())
        shutil.copy2(REPO / ".gitignore", self.repo / ".gitignore")
        env = mock.patch.dict(os.environ, isolated_env(self.home), clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.git("init", "-q")
        self.git("config", "user.email", NOREPLY)
        spec = importlib.util.spec_from_file_location("auto_update_under_test", self.repo / "tools" / "auto_update.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def gate(self):
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            try:
                self.mod.privacy_gate()
            except RuntimeError as error:
                return str(error), log.getvalue()
        return None, log.getvalue()

    def assertBlocked(self, name, data, expected):
        write(self.repo / name, data)
        try:
            blocked, log = self.gate()
            self.assertIsNotNone(blocked, f"{name} should be blocked: {data!r}\n{log}")
            self.assertIn(expected, blocked)
        finally:
            (self.repo / name).unlink()

    def assertClean(self, name, data):
        write(self.repo / name, data)
        try:
            blocked, log = self.gate()
            self.assertIsNone(blocked, f"{name} should pass: {data!r}")
            return log
        finally:
            (self.repo / name).unlink()

    def test_scratch_repository_starts_clean(self):
        blocked, log = self.gate()
        self.assertIsNone(blocked)
        self.assertIn("privacy gate: clean", log)

    def test_share_links_in_any_case_and_with_short_or_encoded_secrets(self):
        samples = [
            link("vless", "0123456789abcdef@host.example.com:443"),
            link("VLESS", "0123456789ABCDEF@host.example.com:443"),
            link("Trojan", "pw12@203.0.113.9:443"),
            link("hy2", "fakepass@203.0.113.9:443"),
            link("ss", "YWVz%3Afake@198.51.100.7:8388"),
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertBlocked("notes.md", f"node: {sample}\n", "proxy share link")

    def test_proxy_urls_with_credentials(self):
        self.assertBlocked("notes.md", link("socks5", "kit-user:" + "Sx9fakepw" + "@198.51.100.4:1080") + "\n",
                           "URL with embedded credentials")
        self.assertBlocked("notes.md", link("http", "kit-user:" + "Sx9fakepw" + "@proxy.example.com:8080") + "\n",
                           "URL with embedded credentials")
        self.assertClean("notes.md", link("http", "user:password@127.0.0.1:7890") + "\n")
        self.assertClean("notes.md", link("socks5", "127.0.0.1:10808") + "\n")

    def test_utf16_and_bom_files_are_decoded_before_scanning(self):
        text = "node: " + link("vless", "0123456789abcdef@host.example.com:443") + "\r\n"
        self.assertBlocked("probe.txt", codecs.BOM_UTF16_LE + text.encode("utf-16-le"), "proxy share link")
        self.assertBlocked("probe.txt", codecs.BOM_UTF16_BE + text.encode("utf-16-be"), "proxy share link")
        self.assertBlocked("probe.txt", codecs.BOM_UTF8 + text.encode("utf-8"), "proxy share link")

    def test_home_paths_of_any_length_are_blocked(self):
        for path in ("C:\\Users\\" + "li" + "\\AppData\\x", "C:/Users/" + "zqfake" + "/Desktop",
                     "/home/" + "li" + "/.config", "/Users/" + "zqfake" + "/Library",
                     "/mnt/c/Users/" + "zqfake" + "/x", '"C:\\\\Users\\\\' + "zqfake" + '\\\\x"'):
            with self.subTest(path=path):
                self.assertBlocked("notes.md", f"path: {path}\n", "user home path")

    def test_placeholder_home_paths_pass(self):
        for path in ("C:\\Users\\<USER>\\claude-backups", "C:\\Users\\<你的用户名>\\x", "C:\\Users\\%USERNAME%\\x",
                     "C:\\Users\\${env:USERNAME}\\x", "/Users/user/kit", "/home/runner/work/kit", "/home/alice/x",
                     "/Users/yourname/Library", "/Users/Shared/x", "C:\\Users\\Public\\x", "/home/$USER/x",
                     "https://example.com/Users/" + "zqfake", "~/claude-backups"):
            with self.subTest(path=path):
                self.assertClean("notes.md", f"path: {path}\n")

    def test_sample_names_are_checked_when_they_are_the_current_account(self):
        for name in ("Dave", "alice", "John", "demo"):
            with self.subTest(name=name):
                patterns = self.mod.identity_patterns([name], [], True)
                text = "C:\\Users\\" + name + "\\AppData\\Local\\x and /home/" + name.lower() + "/proj\n"
                labels = [label for _, label, _ in self.mod.scan_text(text, patterns)]
                self.assertIn("home directory username", labels)
        with mock.patch.dict(os.environ, {"USERNAME": "Dave"}):
            self.assertBlocked("notes.md", "Backup lives in C:\\Users\\Dave\\Documents\\kit\n",
                               "home directory username")
        for name in ("runner", "root", "vscode"):
            with self.subTest(name=name):
                patterns = self.mod.identity_patterns([name], [], True)
                self.assertEqual(self.mod.scan_text("/home/" + name + "/work/kit\n", patterns), [])

    def test_short_account_name_gets_a_home_path_check(self):
        patterns = self.mod.identity_patterns(["li"], [], False)
        labels = [label for _, label, _ in self.mod.scan_text("see /home/" + "li" + "/notes\n", patterns)]
        self.assertIn("home directory username", labels)

    def test_bare_windows_account_name_needs_word_boundaries(self):
        name = "Kit" + "mark"
        patterns = self.mod.identity_patterns([name], [], True)
        self.assertEqual(self.mod.scan_text(name + "down notes, cross-" + name + "s\n", patterns), [])
        labels = [label for _, label, _ in self.mod.scan_text("written by " + name + ".\n", patterns)]
        self.assertIn("Windows username", labels)

    def test_login_behind_a_noreply_address_is_checked(self):
        self.git("config", "user.email", "12345+" + "kitfakelogin" + "@users.noreply.github.com")
        self.assertBlocked("notes.md", "mail me: " + "kitfakelogin" + "@mail.invalid\n", "account e-mail prefix")

    def test_e_mail_addresses_outside_the_allow_list(self):
        self.assertBlocked("notes.md", "contact: " + "zq.fake" + "@" + "not-a-real-domain.zz\n", "e-mail address")
        self.assertClean("notes.md", "someone@example.com, git@github.com, logo" + "@2x.png, "
                         "99999+" + "someone-else" + "@users.noreply.github.com\n")

    def test_unknown_binary_is_blocked_and_known_binary_is_listed_unscanned(self):
        self.assertBlocked("blob.dat", b"\x00\x01\x02binary", "binary content of an unknown type")
        log = self.assertClean("photo.png", b"\x89PNG\r\n\x1a\n" + link("vless", "0123456789abcdef@h.example.com").encode())
        self.assertIn("NOT scanned", log)
        self.assertIn("photo.png", log)

    def test_files_that_gitignore_keeps_out_are_not_scanned(self):
        self.assertClean("run.log", "node: " + link("vless", "0123456789abcdef@host.example.com:443") + "\n")

    def test_ignored_private_copies_at_the_root_do_not_block_until_added(self):
        write(self.repo / "research-reports" / "a.md", "local copy\n")
        write(self.repo / "THIRD-PARTY-NOTICE.md", "old notice\n")
        blocked, _ = self.gate()
        self.assertIsNone(blocked)
        self.git("add", "-f", "research-reports/a.md")
        blocked, _ = self.gate()
        self.assertIsNotNone(blocked)
        self.assertIn("research-reports/a.md", blocked)

    def test_symbolic_link_is_scanned_as_the_path_it_points_to(self):
        if not can_symlink(self.repo):
            self.skipTest("symbolic links are not available")
        os.symlink("/home/" + "zqfake" + "/private/notes.md", self.repo / "notes-link.md")
        blocked, _ = self.gate()
        self.assertIsNotNone(blocked)
        self.assertIn("notes-link.md:1: user home path", blocked)

    def test_private_names_are_blocked_at_any_depth_once_tracked(self):
        write(self.repo / "docs" / "research-reports" / "a.md", "copied article\n")
        self.git("add", "-f", "docs/research-reports/a.md")
        blocked, _ = self.gate()
        self.assertIsNotNone(blocked)
        self.assertIn("docs/research-reports/a.md", blocked)


class RealTreeGateTest(unittest.TestCase):
    def test_this_checkout_passes_the_gate_with_a_neutral_identity(self):
        reason = skip_reason()
        if reason:
            self.skipTest(reason)
        listing = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=REPO,
                                 capture_output=True, text=True, encoding="utf-8")
        if listing.returncode:
            # Not only "not a git checkout": git also refuses a folder another account owns.
            message = (listing.stderr.strip().splitlines() or ["no message"])[0]
            self.skipTest(f"git does not list this folder: {message}")
        names = [name for name in listing.stdout.split("\0") if name and (REPO / name).is_file()]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / FAKE_USER
            write(home / ".gitconfig", "")
            copy = root / "repo"
            for name in names:
                write(copy / name, (REPO / name).read_bytes())
            with mock.patch.dict(os.environ, isolated_env(home), clear=True):
                subprocess.run(["git", "init", "-q"], cwd=copy, check=True)
                spec = importlib.util.spec_from_file_location("auto_update_real_tree", copy / "tools" / "auto_update.py")
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                with contextlib.redirect_stdout(io.StringIO()):
                    mod.privacy_gate()


if __name__ == "__main__":
    unittest.main()
