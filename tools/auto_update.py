"""Sync the local privacy kit into this repository, gate it, commit and package it.

Steps: clean working tree check -> sync plan -> sync -> privacy gate -> unit tests
-> optional allowlist preview -> git commit -> release ZIP -> git push (only with --push).

Protective rules:
- Nothing starts while the working tree has uncommitted changes, or while tracked files are
  marked assume-unchanged or skip-worktree (git status cannot show local edits to those).
- A failure before the commit puts back only the files this run wrote, replaced or
  removed. Nothing else in the working tree is touched.
- A tracked file whose latest commit was made by hand is not overwritten or deleted
  by the source directory unless --source-wins is given.
- A file the repository does not track yet is only added when named with --allow-new, and
  never over a file of that name that is already in the working tree.
- The sync stops before writing when a file it would add, replace or delete is a symbolic
  link or Windows directory junction (or sits in a linked folder), or differs in the working
  tree from the last commit.
- A new file whose name differs from a tracked file only in letter case stops the sync:
  Windows and macOS treat the two names as one file.
- Local tool output and anything .gitignore ignores is never copied in.
- Nothing is pushed unless --push is given.

Exit codes: 0 done; 1 failed, this run's file changes were put back; 2 refused before
changing anything; 3 failed or interrupted once the commit was made (packaging or pushing),
local commits kept; 130 interrupted before the commit, this run's file changes were put back.
"""
import argparse
import codecs
import datetime
import hashlib
import locale
import os
import re
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOME = Path.home()
DEFAULT_SOURCE = Path(os.environ.get(
    "PRIVACY_KIT_SOURCE", HOME / "LocalProxyNetwork" / "privacy-environment-kit"))
DEFAULT_OUTPUTS = Path(os.environ.get(
    "PRIVACY_KIT_OUTPUTS", HOME / "Documents" / "Codex" / "2026-11-22" / "2023" / "outputs"))
DEFAULT_ALLOWLIST_DIR = HOME / "LocalProxyNetwork" / "reports" / "allowlist-previews"
AUTO_COMMIT_PREFIX = "auto-update: "
REPO_ONLY = {
    ".git", ".gitignore", ".gitattributes", ".github",
    "LICENSE", "THIRD-PARTY-NOTICES.md", "CHANGELOG.md",
    "README.md", "CLAUDE-PROXY-OPTIMIZATION-GUIDE.md", "PRIVACY-CHECKLIST.md",
    "docs", "tools", "AUTO-UPDATE.md", "test_public_release.py", "test_auto_update.py",
}
EXCLUDED_NAMES = {
    "__pycache__", "routing-global.json", ".pytest_cache",
    "research-reports", "sources", "THIRD-PARTY-NOTICE.md",
}
# Output that the kit's own documentation tells people to generate next to the scripts.
LOCAL_OUTPUT_NAMES = {"env-health.html", "evidence"}
LOCAL_OUTPUT_SUFFIXES = {".wfw", ".jsonl"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pdf", ".webp", ".ico"}
PROXY_LINK = re.compile(
    r"\b(?:vless|vmess|trojan|hysteria2?|hy2|tuic|ssr?)://[A-Za-z0-9+/=_%@:.-]{8,}", re.IGNORECASE)
CREDENTIAL_URL = re.compile(
    r"\b(?:socks(?:4a?|5h?)?|https?)://[^\s/@:'\"<>`]+:(?P<secret>[^\s/@'\"<>`]+)@[A-Za-z0-9\[]",
    re.IGNORECASE)
USER_HOME_PATH = re.compile(
    r"(?:(?<![A-Za-z0-9])[A-Za-z]:(?:/+|\\+)(?i:users)"
    r"|(?<![A-Za-z0-9._~-])/(?:mnt/)?[A-Za-z]/(?i:users)"
    r"|(?<![A-Za-z0-9._~-])/(?:home|Users))"
    r"(?:/+|\\+)(?P<user>[^/\\\s\"'<>|:*?`]+)")
EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])(?P<local>[A-Za-z0-9][A-Za-z0-9._%+-]*)"
    r"@(?P<domain>(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![A-Za-z0-9-])")
# Account names that are common words in this kit: never searched for as bare text.
GENERIC_USERS = {
    "runner", "runneradmin", "root", "ubuntu", "admin", "administrator",
    "user", "github", "vscode", "claude", "celeste", "proxy", "privacy",
}
# Built-in, CI and container accounts and shared profile folders. Only these skip the
# home path check for the account that runs the gate: their home paths show up in CI
# logs and examples and say nothing about a person.
SYSTEM_USERS = {
    "runner", "runneradmin", "root", "ubuntu", "administrator", "user", "vscode", "claude",
    "codespace", "docker", "node", "linuxbrew", "debian", "ec2-user", "azureuser",
    "public", "default", "shared", "all",
}
# Sample person names used in documentation and test data.
PLACEHOLDER_NAMES = {
    "alice", "bob", "carol", "dave", "eve", "mallory", "jdoe", "john", "jane", "johndoe", "janedoe",
}
# Words that stand for "whoever you are" in documentation and test data.
PLACEHOLDER_WORDS = {
    "admin", "app", "pi", "guest",
    "username", "users", "you", "your", "yourname", "your-name", "your_name", "youruser",
    "yourusername", "name", "me", "myname", "someone", "somebody", "example", "sample",
    "demo", "test", "tester", "testuser", "foo", "bar", "baz",
    "xxx", "你的用户名", "用户名", "用户", "某用户", "名字", "你的名字",
}
# A home path with one of these names is not private, unless it is the name of the
# account that runs the gate (identity_patterns checks that one separately).
PLACEHOLDER_USERS = SYSTEM_USERS | PLACEHOLDER_NAMES | PLACEHOLDER_WORDS
# File types that look like the end of an e-mail address in names such as "logo@2x.png".
NOT_EMAIL_SUFFIXES = {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js"}
PLACEHOLDER_SECRETS = {
    "pass", "password", "passwd", "pwd", "secret", "token", "yourpassword", "your-password",
    "your_password", "changeme", "密码", "口令",
}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com"}
ALLOWED_EMAIL_DOMAIN_SUFFIXES = (
    ".example", ".invalid", ".test", ".localhost", ".example.com", ".example.org", ".example.net")
ALLOWED_EMAIL_LOCALS = {"git", "noreply", "no-reply"}
FORBIDDEN_MIRROR_MARKERS = ("微信原件", "逆向国外 AI Cloud")
BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
)
# Reparse tag of a Windows directory junction (mklink /J). The stat module only defines it on Windows.
IO_REPARSE_TAG_MOUNT_POINT = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)


class Refused(Exception):
    """The run stopped before anything in the repository was changed."""


class SyncPlan:
    """What a sync would do, worked out before the first write."""

    def __init__(self):
        self.wanted = 0
        self.add, self.replace, self.remove = [], [], []
        self.ignored, self.same_for_git = [], 0


class Touched:
    """What this run changed in the working tree, recorded before each write."""

    def __init__(self):
        self.restore, self.new, self.folders = [], [], []


def log(message):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {message}", flush=True)


def run(cmd, cwd=None, check=True, stdin=None, encoding="utf-8"):
    result = subprocess.run(cmd, cwd=cwd or REPO, capture_output=True, text=True,
                            encoding=encoding, errors="replace", input=stdin)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def python_output_encoding():
    """The encoding a child Python process started with this environment writes to a pipe.

    Piped output is in the locale encoding (cp950 or cp936 on Chinese Windows), not UTF-8,
    unless PYTHONIOENCODING or UTF-8 mode says otherwise. PYTHONIOENCODING is not set for the
    child on purpose: the unit tests start Python processes of their own and read their output
    in the locale encoding, and the variable would reach those processes too.
    """
    forced = os.environ.get("PYTHONIOENCODING", "").partition(":")[0].strip()
    if forced:
        try:
            return codecs.lookup(forced).name
        except LookupError:
            pass
    return locale.getpreferredencoding(False)


def git(*args, check=True, stdin=None):
    # Paths are always literal: a file named "notes[1].md" must not also match "notes1.md".
    return run(["git", "--literal-pathspecs", *args], check=check, stdin=stdin)


def chunks(items, size=50):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def local_identity():
    """Account names and e-mail addresses of whoever runs the gate. Never printed."""
    users = []
    for name in (os.environ.get("USERNAME"), HOME.name):
        if name and name not in users:
            users.append(name)
    emails = []
    for cmd in (["git", "config", "user.email"], ["git", "config", "--global", "user.email"]):
        try:
            email = run(cmd, check=False).stdout.strip()
        except OSError:
            break  # git is not installed: only the account-specific e-mail checks are lost
        if email and "@" in email and email.lower() not in (seen.lower() for seen in emails):
            emails.append(email)
    return users, emails


def identity_patterns(users, emails, windows):
    patterns = []
    for user in users:
        lowered = user.lower()
        if lowered not in SYSTEM_USERS:
            patterns.append((
                "home directory username",
                re.compile(r"(?:[A-Za-z]:[/\\]+Users|/(?:home|Users))[/\\]+" + re.escape(user) + r"(?![A-Za-z0-9_.-])", re.IGNORECASE),
            ))
        # Placeholder names are listed in this file, so as bare words they would always be found.
        if windows and len(user) >= 4 and lowered not in GENERIC_USERS | PLACEHOLDER_USERS:
            patterns.append((
                "Windows username",
                re.compile(r"(?<![A-Za-z0-9])" + re.escape(user) + r"(?![A-Za-z0-9])", re.IGNORECASE),
            ))
    for email in emails:
        patterns.append(("account e-mail", re.compile(re.escape(email), re.IGNORECASE)))
        local, domain = email.rsplit("@", 1)
        if domain.lower() == "users.noreply.github.com":
            local = local.split("+", 1)[-1]  # "<id>+<login>": the login often starts the real address
        elif "noreply" in email.lower():
            continue
        if len(local) >= 4 and local.lower() not in PLACEHOLDER_USERS:
            patterns.append(("account e-mail prefix", re.compile(re.escape(local) + r"@", re.IGNORECASE)))
    return patterns


def forbidden_patterns():
    users, emails = local_identity()
    return [("proxy share link", PROXY_LINK)] + identity_patterns(users, emails, os.name == "nt")


def is_placeholder_user(name):
    name = name.rstrip(".,;)]}").lower()
    return (not name or name in PLACEHOLDER_USERS or name[0] in "$%{[(*~"
            or not any(ch.isalnum() for ch in name))


def is_placeholder_secret(secret):
    lowered = secret.lower()
    return (lowered in PLACEHOLDER_SECRETS or secret[0] in "$%{[(*"
            or set(lowered) <= {"x", "*"} or not any(ch.isalnum() for ch in secret))


def is_allowed_email(local, domain):
    local, domain = local.lower(), domain.lower()
    return (local in ALLOWED_EMAIL_LOCALS or domain in ALLOWED_EMAIL_DOMAINS
            or domain.endswith(ALLOWED_EMAIL_DOMAIN_SUFFIXES)
            or domain.rsplit(".", 1)[-1] in NOT_EMAIL_SUFFIXES)


def scan_text(text, patterns):
    """Return (first line, label, count) for each kind of private content found in ``text``."""
    found = {}

    def note(label, position):
        line, count = found.get(label, (text.count("\n", 0, position) + 1, 0))
        found[label] = (line, count + 1)

    for label, pattern in patterns:
        for match in pattern.finditer(text):
            note(label, match.start())
    for match in CREDENTIAL_URL.finditer(text):
        if not is_placeholder_secret(match.group("secret")):
            note("URL with embedded credentials", match.start())
    for match in USER_HOME_PATH.finditer(text):
        if not is_placeholder_user(match.group("user")):
            note("user home path", match.start())
    for match in EMAIL.finditer(text):
        if not is_allowed_email(match.group("local"), match.group("domain")):
            note("e-mail address", match.start())
    return [(line, label, count) for label, (line, count) in found.items()]


def decode_for_scan(data):
    """Decode file bytes for scanning; None means binary content of an unknown type."""
    for bom, encoding in BOMS:
        if data.startswith(bom):
            return data.decode(encoding, errors="ignore")
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="ignore")


def is_excluded(rel):
    """Private mirrors, caches and local tool output never take part in the sync."""
    return (any(part in EXCLUDED_NAMES or part in LOCAL_OUTPUT_NAMES for part in rel.parts)
            or rel.suffix.lower() in LOCAL_OUTPUT_SUFFIXES)


def in_sync_scope(rel):
    return not is_excluded(rel) and rel.parts[0] != ".git" and rel.parts[0] not in REPO_ONLY


def kit_files(root, skip_repo_only):
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if is_excluded(rel) or rel.parts[0] == ".git":
            continue
        if skip_repo_only and rel.parts[0] in REPO_ONLY:
            continue
        if path.is_file():
            yield rel


def head_blobs():
    """Map every file tracked at HEAD to its blob id."""
    blobs = {}
    for entry in git("ls-tree", "-r", "-z", "HEAD").stdout.split("\0"):
        if entry:
            meta, name = entry.split("\t", 1)
            blobs[name] = meta.split()[2]
    return blobs


def ignored_by_git(names):
    """Return the paths that .gitignore keeps out of commits."""
    if not names:
        return set()
    # check-ignore reads plain paths and refuses the --literal-pathspecs option.
    result = run(["git", "check-ignore", "-z", "--stdin"], check=False, stdin="\0".join(names) + "\0")
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git check-ignore failed:\n{result.stderr}")
    return {name for name in result.stdout.split("\0") if name}


def changed_by_hand(name):
    """True when the latest commit that touched ``name`` was not made by this script."""
    subject = git("log", "-1", "--format=%s", "--", name).stdout.strip()
    return not subject.startswith(AUTO_COMMIT_PREFIX)


def allow_new_names(values):
    names = []
    for value in values:
        name = value.strip().replace("\\", "/")
        while name.startswith("./"):
            name = name[2:]
        if not name or name.startswith("/") or re.match(r"[A-Za-z]:", name) or ".." in name.split("/"):
            raise Refused(f"--allow-new takes a file path relative to the repository root, not {value!r}")
        names.append(name)
    return names


def plan_sync(source, allow_new=(), source_wins=False):
    """Work out what the sync would do. Raises Refused, with nothing written, when a person must decide."""
    if not (source / "README.md").is_file():
        raise Refused(f"Kit source not found: {source}")
    tracked = head_blobs()
    wanted = list(kit_files(source, skip_repo_only=True))
    wanted_names = {rel.as_posix() for rel in wanted}
    plan = SyncPlan()
    plan.wanted = len(wanted)

    new_names = sorted(wanted_names - set(tracked))
    ignored = ignored_by_git(new_names)
    plan.ignored = [name for name in new_names if name in ignored]
    # Windows and macOS keep one file for names that differ only in letter case, so adding
    # "Foo.ps1" and deleting "foo.ps1" would write a file and then delete it again.
    tracked_folded = {}
    for name in tracked:
        tracked_folded.setdefault(name.casefold(), []).append(name)
    case_only = [(name, old) for name in new_names if name not in ignored
                 for old in tracked_folded.get(name.casefold(), ())]
    case_new = {name for name, _ in case_only}
    case_old = {old for _, old in case_only}
    new_names = [name for name in new_names if name not in case_new]
    for name in allow_new:
        if name in ignored:
            raise Refused(f"--allow-new {name}: .gitignore ignores this path, so it can never be committed")
        if name in tracked or name in wanted_names:
            continue
        if not in_sync_scope(Path(name)):
            raise Refused(f"--allow-new {name}: this path is never synced (private name, local output, "
                          "or a file that is maintained in the repository)")
        log(f"sync: note: --allow-new {name} matches no new file in the source directory")
    blocked = [name for name in new_names if name not in ignored and name not in allow_new]
    plan.add = [Path(name) for name in new_names if name not in ignored and name in allow_new]

    for rel in wanted:
        name = rel.as_posix()
        if name not in tracked:
            continue
        src, dst = source / rel, REPO / rel
        if dst.is_file() and dst.read_bytes() == src.read_bytes():
            continue
        if git("hash-object", f"--path={name}", "--", str(src)).stdout.strip() == tracked[name]:
            plan.same_for_git += 1  # differs only in what git normalises, such as line endings
            continue
        plan.replace.append(rel)
    plan.remove = [Path(name) for name in sorted(tracked)
                   if name not in wanted_names and name not in case_old and in_sync_scope(Path(name))]

    # git status can miss local edits (assume-unchanged, skip-worktree, untracked files
    # hidden by configuration), and copying onto a link writes to whatever it points to.
    unsafe = []
    for rel in plan.add + plan.replace + plan.remove:
        name = rel.as_posix()
        if involves_link(source, rel):
            unsafe.append(f"{name}  (a symbolic link or directory junction, or inside a linked folder)")
        elif rel in plan.add:
            if os.path.lexists(REPO / rel):
                unsafe.append(f"{name}  (already in the working tree, although git does not track it)")
        elif worktree_blob(name) != tracked[name]:
            unsafe.append(f"{name}  (the working tree copy differs from the last commit)")

    conflicts = []
    if not source_wins:
        conflicts += [f"{rel.as_posix()}  (would be overwritten)" for rel in plan.replace if changed_by_hand(rel.as_posix())]
        conflicts += [f"{rel.as_posix()}  (would be deleted)" for rel in plan.remove if changed_by_hand(rel.as_posix())]
    if blocked or conflicts or unsafe or case_only:
        lines = ["sync stopped before changing anything."]
        if case_only:
            lines.append("  New files whose names differ from a tracked file only in letter case. Windows "
                         "and macOS treat both names as one file, so the sync cannot add one and delete "
                         "the other. If only the case changed, rename the file in the repository "
                         "('git mv OLD NEW'), commit, then run again; otherwise rename it in the source "
                         "directory:")
            lines += [f"    {name}  (tracked as {old})" for name, old in case_only]
        if unsafe:
            lines.append("  Files the sync would write or delete but cannot do so safely. Sort them out "
                         "by hand ('git status --untracked-files=all', 'git ls-files -v'), then run again:")
            lines += [f"    {entry}" for entry in unsafe]
        if blocked:
            lines.append("  New files that the repository does not track yet. Name each one with "
                         "--allow-new PATH if it belongs in the public repository, or keep it out "
                         "of the source directory:")
            lines += [f"    {name}" for name in blocked]
        if conflicts:
            lines.append("  Tracked files that were changed by hand in the repository after the last "
                         "automatic sync. Copy them back to the source directory, or pass "
                         "--source-wins to let the source directory overwrite or delete them:")
            lines += [f"    {entry}" for entry in conflicts]
        raise Refused("\n".join(lines))
    return plan


def is_link(path):
    """True for a symbolic link, and for a Windows directory junction, which os.path.islink misses."""
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        return False
    return stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", None) == IO_REPARSE_TAG_MOUNT_POINT


def involves_link(source, rel):
    """True when ``rel`` or a folder above it is a link or junction in the source or the repository."""
    for root in (source, REPO):
        for depth in range(1, len(rel.parts) + 1):
            if is_link(root.joinpath(*rel.parts[:depth])):
                return True
    return False


def worktree_blob(name):
    """Blob id git would store for the working tree copy of ``name``; None when it is missing."""
    path = REPO / name
    if not path.is_file():
        return None
    return git("hash-object", f"--path={name}", "--", str(path)).stdout.strip()


def summarize_names(names):
    """One line per top-level folder with its file count, so a .venv/ does not flood the log."""
    groups = {}
    for name in names:
        top, sep, _ = name.partition("/")
        key = top + "/" if sep else name
        groups[key] = groups.get(key, 0) + 1
    return [f"{key} ({count} file{'' if count == 1 else 's'})" if key.endswith("/") else key
            for key, count in groups.items()]


def report_plan(plan):
    log(f"sync: {plan.wanted} kit files in the source directory; {len(plan.add)} new, "
        f"{len(plan.replace)} replaced, {len(plan.remove)} removed, "
        f"{len(plan.ignored)} skipped (ignored by .gitignore), "
        f"{plan.same_for_git} left alone (same content for git)")
    for title, rels in (("new", plan.add), ("replaced", plan.replace), ("removed", plan.remove)):
        for rel in rels:
            log(f"sync:   {title}: {rel.as_posix()}")
    for entry in summarize_names(plan.ignored):
        log(f"sync:   skipped: {entry}")


def apply_sync(plan, source, touched):
    """Carry out the plan. Every path is recorded before it is written so a failure can undo it."""
    for rel in plan.add + plan.replace:
        dst = REPO / rel
        touched.folders += [folder for folder in dst.parents
                            if REPO in folder.parents and not folder.exists() and folder not in touched.folders]
        (touched.new if rel in plan.add else touched.restore).append(rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / rel, dst)
    for rel in plan.remove:
        touched.restore.append(rel)
        (REPO / rel).unlink()
        folder = (REPO / rel).parent
        while folder != REPO and not any(folder.iterdir()):
            folder.rmdir()
            folder = folder.parent


def undo_sync(touched):
    """Put back exactly what this run wrote, replaced or removed, and nothing else."""
    restore = [rel.as_posix() for rel in touched.restore]
    new = [rel.as_posix() for rel in touched.new]
    if not restore and not new:
        return
    problems = []
    restored = removed = 0
    for chunk in chunks(restore + new):
        git("reset", "-q", "HEAD", "--", *chunk, check=False)
    for chunk in chunks(restore):
        if git("checkout", "-q", "HEAD", "--", *chunk, check=False).returncode == 0:
            restored += len(chunk)
            continue
        for name in chunk:  # find out which ones could not be put back
            result = git("checkout", "-q", "HEAD", "--", name, check=False)
            if result.returncode:
                problems.append(result.stderr.strip() or f"could not restore {name}")
            else:
                restored += 1
    for name in new:
        try:
            if os.path.lexists(REPO / name):
                (REPO / name).unlink()
                removed += 1
        except OSError as error:
            problems.append(str(error))
    for folder in sorted(touched.folders, key=lambda path: len(path.parts), reverse=True):
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    log(f"rollback: restored {restored} of {len(restore)} tracked file(s) from HEAD and removed {removed} "
        f"of {len(new)} new file(s) written by this run; nothing else in the working tree was touched")
    for problem in problems:
        log(f"rollback: PROBLEM, check 'git status': {problem}")


def gate_candidates():
    """Files the gate reads: what git tracks or would add. Without git, walk the folder."""
    try:
        listing = git("ls-files", "-co", "--exclude-standard", "-z", check=False)
    except OSError:
        listing = None
    if listing is None or listing.returncode:
        return list(kit_files(REPO, skip_repo_only=False))
    names = {name for name in listing.stdout.split("\0") if name}
    return [Path(name) for name in sorted(names) if os.path.islink(REPO / name) or (REPO / name).is_file()]


def privacy_gate():
    patterns = forbidden_patterns()
    hits, unscanned, lossy, scanned = [], [], [], 0
    for rel in gate_candidates():
        posix_path = rel.as_posix()
        if any(part in EXCLUDED_NAMES for part in rel.parts):
            hits.append(f"{posix_path}: private or cache name that must stay out of the public repo")
            continue
        if any(marker in posix_path for marker in FORBIDDEN_MIRROR_MARKERS):
            hits.append(f"{posix_path}: forbidden third-party mirror filename")
        if os.path.islink(REPO / rel):
            # git commits a link as the path it points to, not as the content behind it.
            data = os.readlink(REPO / rel).encode("utf-8", "surrogateescape")
        elif rel.suffix.lower() in BINARY_SUFFIXES:
            unscanned.append(posix_path)
            continue
        else:
            data = (REPO / rel).read_bytes()
        text = decode_for_scan(data)
        if text is None:
            hits.append(f"{posix_path}: binary content of an unknown type cannot be scanned "
                        "(review the file, then add its suffix to BINARY_SUFFIXES)")
            continue
        scanned += 1
        if not data.startswith(tuple(bom for bom, _ in BOMS)):
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                lossy.append(posix_path)
        for line, label, count in scan_text(text, patterns):
            more = f" (+{count - 1} more)" if count > 1 else ""
            hits.append(f"{posix_path}:{line}: {label}{more}")
        for marker in FORBIDDEN_MIRROR_MARKERS:
            if marker in text and rel.name != "auto_update.py" and rel.name != "test_public_release.py":
                hits.append(f"{posix_path}: forbidden mirror marker ({marker})")
    if unscanned:
        log("privacy gate: NOT scanned (binary, review by eye): " + ", ".join(unscanned))
    if lossy:
        log("privacy gate: not valid UTF-8, scanned with undecodable bytes dropped: " + ", ".join(lossy))
    if hits:
        raise RuntimeError("privacy gate blocked the update:\n  " + "\n  ".join(hits))
    log(f"privacy gate: clean ({scanned} files scanned, {len(patterns)} account checks plus the generic ones)")


def unit_tests():
    result = run([sys.executable, "-B", "-m", "unittest", "discover", "-p", "test_*.py", "-v"], check=False,
                 encoding=python_output_encoding())
    lines = result.stderr.splitlines()
    summary = [line for line in lines if line.startswith(("Ran ", "OK", "FAILED"))]
    if result.returncode:
        raise RuntimeError("unit tests failed:\n" + result.stderr[-4000:])
    log("tests: " + " | ".join(summary))
    skipped = [line.strip() for line in lines if " ... skipped " in line]
    if skipped:
        log(f"tests: NOTE {len(skipped)} skipped, so they checked nothing on this computer:\n  "
            + "\n  ".join(skipped))


def refresh_allowlists(directory):
    result = run([sys.executable, "-B", str(REPO / "refresh_allowlists.py"),
                  "--output-directory", str(directory), "--max-age-hours", "168"], check=False,
                 encoding=python_output_encoding())
    tail = (result.stdout or result.stderr).strip().splitlines()[-1:] or [""]
    if result.returncode:
        log(f"allowlist preview: skipped (warning, not fatal): {tail[0]}")
    else:
        log(f"allowlist preview: {tail[0]}")


def kit_version():
    report = REPO / "environment_report.py"
    if report.is_file():
        match = re.search(r'^KIT_VERSION\s*=\s*["\'](\d+\.\d+\.\d+)["\']',
                          report.read_text(encoding="utf-8"), re.MULTILINE)
        if match:
            return match.group(1)
    match = re.search(r"v(\d+\.\d+\.\d+)", (REPO / "README.md").read_text(encoding="utf-8"))
    return match.group(1) if match else "0.0.0"


def build_zip(outputs):
    """Package the committed files with ``git archive``, the same rule the release workflow uses."""
    version = kit_version()
    stamp = datetime.date.today().isoformat()
    outputs.mkdir(parents=True, exist_ok=True)
    target = outputs / f"cross-platform-privacy-environment-kit-v{version}-{stamp}.zip"
    prefix = f"cross-platform-privacy-environment-kit-v{version}/"
    tmp = target.with_name(target.name + ".part")
    try:
        git("archive", "--format=zip", f"--prefix={prefix}", "-o", str(tmp), "HEAD")
        with zipfile.ZipFile(tmp) as archive:
            if archive.testzip() is not None:
                raise RuntimeError("release ZIP failed its integrity check")
            entries = sum(1 for name in archive.namelist() if not name.endswith("/"))
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    log(f"package: {target} ({entries} entries, sha256 {digest[:16]}...)")


def commit(touched):
    """Commit exactly the files this run wrote, replaced or removed."""
    for chunk in chunks([rel.as_posix() for rel in touched.restore + touched.new]):
        git("add", "-A", "--", *chunk)
    if git("diff", "--cached", "--quiet", check=False).returncode == 0:
        log("git: no changes, nothing to commit")
        return False
    log("git: changes in this commit:\n" + git("diff", "--cached", "--stat").stdout.rstrip())
    git("commit", "-q", "-m", f"{AUTO_COMMIT_PREFIX}{datetime.date.today().isoformat()}")
    # From here on the commit exists. If anything below fails, main() sees that HEAD moved and keeps it.
    log("git: committed " + git("rev-parse", "--short", "HEAD", check=False).stdout.strip())
    if non_noreply_emails("-1"):
        log("git: note: this commit carries an author or committer e-mail that is not a noreply "
            "address; it becomes public when the commit is pushed")
    return True


def non_noreply_emails(*revisions):
    """Author and committer e-mails in these commits that are not noreply addresses."""
    listing = git("log", "--format=%ae%n%ce", *revisions, check=False).stdout.split()
    return sorted({email for email in listing if "noreply" not in email.lower()})


def current_branch():
    return git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def pushable_branches():
    """main, plus the default branch of origin when the local clone knows it. Never asks the network."""
    names = {"main"}
    default = git("symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD", check=False).stdout.strip()
    if default.startswith("origin/"):
        names.add(default[len("origin/"):])
    return names


def unpushed_count(branch):
    ahead = git("rev-list", "--count", f"origin/{branch}..HEAD", check=False)
    return int(ahead.stdout.strip()) if ahead.returncode == 0 and ahead.stdout.strip().isdigit() else None


def push():
    if "origin" not in git("remote").stdout.split():
        log("git: no 'origin' remote yet, push skipped")
        return
    branch = current_branch()
    if branch not in pushable_branches():
        raise RuntimeError(f"not pushing: the current branch is '{branch}', not main or the default branch of origin")
    if unpushed_count(branch) == 0:
        log("git: origin already up to date")
        return
    if non_noreply_emails("HEAD", "--not", "--remotes=origin"):
        raise RuntimeError("not pushing: a commit that is not on origin yet carries an author or committer "
                           "e-mail that is not a noreply address, and pushing would publish it "
                           "('git log --format=\"%h %ae %ce\" HEAD --not --remotes=origin' lists them). "
                           "Fix the commits, or push by hand if that address is meant to be public")
    git("push", "-u", "origin", branch)
    log(f"git: pushed {branch} to origin")


def report_unpushed(committed):
    branch = current_branch()
    if committed:
        log("git: this commit exists only on this computer; nothing was pushed. Review it with "
            f"'git show --stat HEAD'; publish it with 'git push origin {branch}' or by running "
            "this script again with --push")
        return
    count = unpushed_count(branch)
    if count:
        log(f"git: {count} local commit(s) are not on origin yet ('git log origin/{branch}..HEAD' "
            "lists them); nothing was pushed because --push was not given")


def hidden_index_entries():
    """Tracked files whose local edits git status does not show: lower-case tag or S in ls-files -v."""
    hidden = []
    for entry in git("ls-files", "-v", "-z").stdout.split("\0"):
        tag, _, name = entry.partition(" ")
        if name and (tag.islower() or tag == "S"):
            hidden.append(f"{name}  ({'skip-worktree' if tag in 'Ss' else 'assume-unchanged'})")
    return hidden


def preflight(args):
    """Everything that must hold before the first write. Raises Refused otherwise."""
    try:
        inside = git("rev-parse", "--is-inside-work-tree", check=False)
    except OSError as error:
        raise Refused(f"git is not available: {error}")
    if inside.returncode or inside.stdout.strip() != "true":
        # git's own message names the cause, e.g. "detected dubious ownership" with the
        # safe.directory command to run when the folder belongs to another account.
        reason = inside.stderr.strip()
        if reason:
            raise Refused(f"git cannot work in {REPO}; git says:\n  " + "\n  ".join(reason.splitlines()))
        raise Refused(f"{REPO} is not a git working tree")
    if git("rev-parse", "-q", "--verify", "HEAD", check=False).returncode:
        raise Refused("the repository has no commit yet; make the first commit by hand")
    # Untracked files are listed even when status.showUntrackedFiles=no is configured.
    dirty = git("status", "--porcelain", "--untracked-files=normal").stdout.rstrip()
    if dirty:
        raise Refused("the working tree has uncommitted changes. Commit, stash or remove them first; "
                      "nothing was changed.\n  " + "\n  ".join(dirty.splitlines()))
    hidden = hidden_index_entries()
    if hidden:
        raise Refused("these tracked files are marked assume-unchanged or skip-worktree, so 'git status' "
                      "cannot show local edits to them. Clear the marks (git update-index "
                      "--no-assume-unchanged / --no-skip-worktree PATH) first; nothing was changed.\n  "
                      + "\n  ".join(hidden))
    if args.push and current_branch() not in pushable_branches():
        raise Refused(f"--push only pushes main or the default branch of origin, and the current branch "
                      f"is '{current_branch()}'. Switch branches or drop --push; nothing was changed.")
    return allow_new_names(args.allow_new)


def head_moved(start_head):
    """True when HEAD is no longer the commit this run started from."""
    if not start_head:
        return False
    try:
        now = git("rev-parse", "-q", "--verify", "HEAD", check=False).stdout.strip()
    except OSError:
        return False
    return bool(now) and now != start_head


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help="Private kit directory to sync from (default: PRIVACY_KIT_SOURCE or the built-in path).")
    parser.add_argument("--outputs", type=Path, default=DEFAULT_OUTPUTS,
                        help="Where the release ZIP is written (default: PRIVACY_KIT_OUTPUTS or the built-in path).")
    parser.add_argument("--refresh-allowlists", action="store_true",
                        help="Also build a weekly China-direct allowlist preview (never applied automatically).")
    parser.add_argument("--allowlist-directory", type=Path, default=DEFAULT_ALLOWLIST_DIR)
    parser.add_argument("--no-sync", action="store_true",
                        help="Skip the sync: only gate, test and package what is already committed.")
    parser.add_argument("--allow-new", action="append", default=[], metavar="PATH",
                        help="Let this not-yet-tracked file in from the source directory. Repeat for each file.")
    parser.add_argument("--source-wins", action="store_true",
                        help="Let the source directory overwrite or delete tracked files that were changed by hand.")
    pushing = parser.add_mutually_exclusive_group()
    pushing.add_argument("--push", action="store_true",
                         help="Push to origin after a successful run. Without it nothing leaves this computer.")
    pushing.add_argument("--no-push", action="store_true",
                         help="Accepted for older command lines; not pushing is the default.")
    parser.add_argument("--force-package", action="store_true",
                        help="Build the release ZIP even when there was nothing to commit.")
    return parser


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    touched = Touched()
    committed = None  # stays None until the commit step has finished
    start_head = None
    try:
        allow_new = preflight(args)
        start_head = git("rev-parse", "HEAD").stdout.strip()
        if not args.no_sync:
            plan = plan_sync(args.source, allow_new, args.source_wins)
            report_plan(plan)
            apply_sync(plan, args.source, touched)
        privacy_gate()
        unit_tests()
        if args.refresh_allowlists:
            refresh_allowlists(args.allowlist_directory)
        committed = commit(touched)
        if committed or args.force_package:
            build_zip(args.outputs)
        if args.push:
            push()
        else:
            report_unpushed(committed)
    except Refused as refusal:
        log(f"REFUSED: {refusal}")
        return 2
    except (Exception, KeyboardInterrupt) as error:
        if committed is None and head_moved(start_head):
            committed = True  # interrupted after git commit, before commit() returned
        if committed is not None:
            log("FAILED after the commit step; local commits stay in the repository and this run "
                f"pushed nothing: {error or type(error).__name__}")
            return 3
        undo_sync(touched)
        log(f"FAILED: {error or type(error).__name__}")
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    leftover = git("status", "--porcelain", "--untracked-files=normal", check=False).stdout.rstrip()
    if leftover:
        log("note: files this run did not write are uncommitted in the working tree:\n  "
            + "\n  ".join(leftover.splitlines()))
    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
