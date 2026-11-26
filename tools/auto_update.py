"""Sync the local privacy kit into this repository, gate it, commit and package it.

Steps: clean working tree check -> sync plan -> sync -> privacy gate -> unit tests
-> optional allowlist preview -> git commit -> release ZIP -> git push (only with --push).

Protective rules:
- Nothing starts while the working tree has uncommitted changes.
- A failure before the commit puts back only the files this run wrote, replaced or
  removed. Nothing else in the working tree is touched.
- A tracked file whose latest commit was made by hand is not overwritten or deleted
  by the source directory unless --source-wins is given.
- A file the repository does not track yet is only added when named with --allow-new.
- Local tool output and anything .gitignore ignores is never copied in.
- Nothing is pushed unless --push is given.

Exit codes: 0 done; 1 failed, this run's file changes were put back; 2 refused before
changing anything; 3 committed locally but packaging or pushing failed.
"""
import argparse
import codecs
import datetime
import hashlib
import os
import re
import shutil
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
# Names that stand for "whoever you are" in documentation and test data.
PLACEHOLDER_USERS = GENERIC_USERS | {
    "username", "users", "you", "your", "yourname", "your-name", "your_name", "youruser",
    "yourusername", "name", "me", "myname", "someone", "somebody", "example", "sample",
    "demo", "test", "tester", "testuser", "foo", "bar", "baz", "alice", "bob", "carol",
    "dave", "eve", "mallory", "jdoe", "john", "jane", "johndoe", "janedoe", "public",
    "default", "shared", "guest", "all", "codespace", "docker", "app", "node", "pi",
    "linuxbrew", "debian", "xxx", "你的用户名", "用户名", "某用户",
}
PLACEHOLDER_SECRETS = {"pass", "password", "passwd", "pwd", "secret", "token", "密码", "口令"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com"}
ALLOWED_EMAIL_DOMAIN_SUFFIXES = (
    ".example", ".invalid", ".test", ".localhost", ".example.com", ".example.org", ".example.net")
ALLOWED_EMAIL_LOCALS = {"git", "noreply", "no-reply"}
FORBIDDEN_MIRROR_MARKERS = ("微信原件", "逆向国外 AI Cloud")
BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
)


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


def run(cmd, cwd=None, check=True, stdin=None):
    result = subprocess.run(cmd, cwd=cwd or REPO, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", input=stdin)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def git(*args, check=True, stdin=None):
    return run(["git", *args], check=check, stdin=stdin)


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
        patterns.append((
            "home directory username",
            re.compile(r"(?:[A-Za-z]:[/\\]+Users|/(?:home|Users))[/\\]+" + re.escape(user) + r"(?![A-Za-z0-9_.-])", re.IGNORECASE),
        ))
        if windows and len(user) >= 4 and user.lower() not in GENERIC_USERS:
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
        if len(local) >= 4:
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
            or domain.endswith(ALLOWED_EMAIL_DOMAIN_SUFFIXES))


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
    result = git("check-ignore", "-z", "--stdin", check=False, stdin="\0".join(names) + "\0")
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
                   if name not in wanted_names and in_sync_scope(Path(name))]

    conflicts = []
    if not source_wins:
        conflicts += [f"{rel.as_posix()}  (would be overwritten)" for rel in plan.replace if changed_by_hand(rel.as_posix())]
        conflicts += [f"{rel.as_posix()}  (would be deleted)" for rel in plan.remove if changed_by_hand(rel.as_posix())]
    if blocked or conflicts:
        lines = ["sync stopped before changing anything."]
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


def report_plan(plan):
    log(f"sync: {plan.wanted} kit files in the source directory; {len(plan.add)} new, "
        f"{len(plan.replace)} replaced, {len(plan.remove)} removed, "
        f"{len(plan.ignored)} skipped (ignored by .gitignore), "
        f"{plan.same_for_git} left alone (same content for git)")
    for title, rels in (("new", plan.add), ("replaced", plan.replace), ("removed", plan.remove)):
        for rel in rels:
            log(f"sync:   {title}: {rel.as_posix()}")
    for name in plan.ignored:
        log(f"sync:   skipped: {name}")


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
    for chunk in chunks(restore + new):
        git("reset", "-q", "HEAD", "--", *chunk, check=False)
    for chunk in chunks(restore):
        result = git("checkout", "-q", "HEAD", "--", *chunk, check=False)
        if result.returncode:
            problems.append(result.stderr.strip())
    for name in new:
        try:
            (REPO / name).unlink(missing_ok=True)
        except OSError as error:
            problems.append(str(error))
    for folder in sorted(touched.folders, key=lambda path: len(path.parts), reverse=True):
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    log(f"rollback: restored {len(restore)} tracked file(s) from HEAD and removed {len(new)} new file(s) "
        "written by this run; nothing else in the working tree was touched")
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
    return [Path(name) for name in sorted(names) if (REPO / name).is_file()]


def privacy_gate():
    patterns = forbidden_patterns()
    hits, unscanned, lossy, scanned = [], [], [], 0
    if (REPO / "research-reports").exists():
        hits.append("research-reports/: mirrored third-party directory is forbidden in public repo")
    if (REPO / "THIRD-PARTY-NOTICE.md").exists():
        hits.append("THIRD-PARTY-NOTICE.md: legacy private notice must stay excluded")
    for rel in gate_candidates():
        posix_path = rel.as_posix()
        if any(part in EXCLUDED_NAMES for part in rel.parts):
            hits.append(f"{posix_path}: private or cache name that must stay out of the public repo")
            continue
        if any(marker in posix_path for marker in FORBIDDEN_MIRROR_MARKERS):
            hits.append(f"{posix_path}: forbidden third-party mirror filename")
        if rel.suffix.lower() in BINARY_SUFFIXES:
            unscanned.append(posix_path)
            continue
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
    result = run([sys.executable, "-B", "-m", "unittest", "discover", "-p", "test_*.py", "-v"], check=False)
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
                  "--output-directory", str(directory), "--max-age-hours", "168"], check=False)
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
    log("git: committed " + git("rev-parse", "--short", "HEAD").stdout.strip())
    if "noreply" not in git("log", "-1", "--format=%ae %ce").stdout.lower():
        log("git: note: this commit carries an author e-mail that is not a noreply address; "
            "it becomes public when the commit is pushed")
    return True


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


def preflight(args):
    """Everything that must hold before the first write. Raises Refused otherwise."""
    try:
        inside = git("rev-parse", "--is-inside-work-tree", check=False)
    except OSError as error:
        raise Refused(f"git is not available: {error}")
    if inside.returncode or inside.stdout.strip() != "true":
        raise Refused(f"{REPO} is not a git working tree")
    if git("rev-parse", "-q", "--verify", "HEAD", check=False).returncode:
        raise Refused("the repository has no commit yet; make the first commit by hand")
    dirty = git("status", "--porcelain").stdout.rstrip()
    if dirty:
        raise Refused("the working tree has uncommitted changes. Commit, stash or remove them first; "
                      "nothing was changed.\n  " + "\n  ".join(dirty.splitlines()))
    if args.push and current_branch() not in pushable_branches():
        raise Refused(f"--push only pushes main or the default branch of origin, and the current branch "
                      f"is '{current_branch()}'. Switch branches or drop --push; nothing was changed.")
    return allow_new_names(args.allow_new)


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
    committed = False
    try:
        allow_new = preflight(args)
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
        if committed:
            log("FAILED after the commit, which stays in the local repository and was not pushed "
                f"by this run: {error or type(error).__name__}")
            return 3
        undo_sync(touched)
        log(f"FAILED: {error or type(error).__name__}")
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    leftover = git("status", "--porcelain", check=False).stdout.rstrip()
    if leftover:
        log("note: files this run did not write are uncommitted in the working tree:\n  "
            + "\n  ".join(leftover.splitlines()))
    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
