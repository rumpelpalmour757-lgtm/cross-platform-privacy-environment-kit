"""Sync the local privacy kit into this repository, gate it, commit, package and push.

Steps: sync -> privacy gate -> unit tests -> optional allowlist preview -> git commit
-> release ZIP -> git push (only when an ``origin`` remote exists).
Any failure before the commit restores the working tree to the last commit.
"""
import argparse
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
REPO_ONLY = {
    ".git", ".gitignore", ".gitattributes", ".github",
    "LICENSE", "THIRD-PARTY-NOTICES.md", "CHANGELOG.md",
    "README.md", "CLAUDE-PROXY-OPTIMIZATION-GUIDE.md", "PRIVACY-CHECKLIST.md",
    "docs", "tools", "AUTO-UPDATE.md", "test_public_release.py",
}
EXCLUDED_NAMES = {
    "__pycache__", "routing-global.json", ".pytest_cache",
    "research-reports", "sources", "THIRD-PARTY-NOTICE.md",
}
PACKAGE_EXCLUDED_TOP = {".git", ".gitignore", ".gitattributes", ".github", "tools", "AUTO-UPDATE.md"}
PACKAGE_EXCLUDED_SUBPATHS = {("docs", "releases")}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pdf", ".webp", ".ico"}
PROXY_LINK = re.compile(r"\b(?:vless|vmess|trojan|hysteria2?|tuic|ssr?)://[A-Za-z0-9+/=_-]{8,}")
FORBIDDEN_MIRROR_MARKERS = ("微信原件", "逆向国外 AI Cloud")


def log(message):
    print(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {message}", flush=True)


def run(cmd, cwd=REPO, check=True):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}")
    return result


def forbidden_patterns():
    patterns = [("proxy share link", PROXY_LINK)]
    user = os.environ.get("USERNAME") or HOME.name
    if len(user) >= 4:
        patterns.append((
            "home directory username",
            re.compile(r"(?:[A-Za-z]:[/\\]+Users|/(?:home|Users))[/\\]+" + re.escape(user) + r"(?![A-Za-z0-9_.-])", re.IGNORECASE),
        ))
        generic_users = {
            "runner", "runneradmin", "root", "ubuntu", "admin", "administrator",
            "user", "github", "vscode", "claude", "celeste", "proxy", "privacy",
        }
        if os.name == "nt" and user.lower() not in generic_users:
            patterns.append(("Windows username", re.compile(re.escape(user), re.IGNORECASE)))
    seen_emails = set()
    for cmd in (["git", "config", "user.email"], ["git", "config", "--global", "user.email"]):
        email = run(cmd, check=False).stdout.strip()
        if not email or "@" not in email or email.lower() in seen_emails:
            continue
        seen_emails.add(email.lower())
        patterns.append(("account e-mail", re.compile(re.escape(email), re.IGNORECASE)))
        local = email.split("@", 1)[0]
        if len(local) >= 4 and "noreply" not in email.lower():
            patterns.append(("account e-mail prefix", re.compile(re.escape(local) + r"@", re.IGNORECASE)))
    return patterns


def kit_files(root, skip_repo_only):
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_NAMES for part in rel.parts) or rel.parts[0] == ".git":
            continue
        if skip_repo_only and rel.parts[0] in REPO_ONLY:
            continue
        if path.is_file():
            yield rel


def sync(source):
    if not (source / "README.md").is_file():
        raise RuntimeError(f"Kit source not found: {source}")
    wanted = set(kit_files(source, skip_repo_only=True))
    changed = 0
    for rel in wanted:
        src, dst = source / rel, REPO / rel
        if dst.is_file() and dst.read_bytes() == src.read_bytes():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        changed += 1
    removed = 0
    for rel in list(kit_files(REPO, skip_repo_only=True)):
        if rel not in wanted:
            (REPO / rel).unlink()
            removed += 1
    for folder in sorted((p for p in REPO.rglob("*") if p.is_dir() and ".git" not in p.parts),
                         key=lambda p: len(p.parts), reverse=True):
        if not any(folder.iterdir()):
            folder.rmdir()
    log(f"sync: {len(wanted)} kit files, {changed} copied, {removed} removed")


def privacy_gate():
    patterns = forbidden_patterns()
    hits = []
    if (REPO / "research-reports").exists():
        hits.append("research-reports/: mirrored third-party directory is forbidden in public repo")
    if (REPO / "THIRD-PARTY-NOTICE.md").exists():
        hits.append("THIRD-PARTY-NOTICE.md: legacy private notice must stay excluded")
    for rel in kit_files(REPO, skip_repo_only=False):
        posix_path = rel.as_posix()
        if any(marker in posix_path for marker in FORBIDDEN_MIRROR_MARKERS):
            hits.append(f"{posix_path}: forbidden third-party mirror filename")
        if rel.suffix.lower() in BINARY_SUFFIXES:
            continue
        text = (REPO / rel).read_text(encoding="utf-8", errors="ignore")
        for label, pattern in patterns:
            if pattern.search(text):
                hits.append(f"{posix_path}: {label}")
        for marker in FORBIDDEN_MIRROR_MARKERS:
            if marker in text and rel.name != "auto_update.py" and rel.name != "test_public_release.py":
                hits.append(f"{posix_path}: forbidden mirror marker ({marker})")
    if hits:
        raise RuntimeError("privacy gate blocked the update:\n  " + "\n  ".join(hits))
    log(f"privacy gate: clean ({len(patterns)} checks)")


def unit_tests():
    result = run([sys.executable, "-B", "-m", "unittest", "discover", "-p", "test_*.py"], check=False)
    summary = [line for line in result.stderr.splitlines() if line.startswith(("Ran ", "OK", "FAILED"))]
    if result.returncode:
        raise RuntimeError("unit tests failed:\n" + result.stderr[-4000:])
    log("tests: " + " | ".join(summary))


def refresh_allowlists(directory):
    result = run([sys.executable, "-B", str(REPO / "refresh_allowlists.py"),
                  "--output-directory", str(directory), "--max-age-hours", "168"], check=False)
    tail = (result.stdout or result.stderr).strip().splitlines()[-1:] or [""]
    if result.returncode:
        log(f"allowlist preview: skipped (warning, not fatal): {tail[0]}")
    else:
        log(f"allowlist preview: {tail[0]}")


def kit_version():
    match = re.search(r"v(\d+\.\d+\.\d+)", (REPO / "README.md").read_text(encoding="utf-8"))
    return match.group(1) if match else "0.0.0"


def build_zip(outputs):
    version = kit_version()
    stamp = datetime.date.today().isoformat()
    outputs.mkdir(parents=True, exist_ok=True)
    target = outputs / f"cross-platform-privacy-environment-kit-v{version}-{stamp}.zip"
    prefix = f"cross-platform-privacy-environment-kit-v{version}/"
    tmp = target.with_name(target.name + ".part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for rel in kit_files(REPO, skip_repo_only=False):
            if rel.parts[0] in PACKAGE_EXCLUDED_TOP:
                continue
            if len(rel.parts) >= 2 and (rel.parts[0], rel.parts[1]) in PACKAGE_EXCLUDED_SUBPATHS:
                continue
            archive.write(REPO / rel, prefix + rel.as_posix())
    with zipfile.ZipFile(tmp) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("release ZIP failed its integrity check")
        entries = len(archive.namelist())
    os.replace(tmp, target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    log(f"package: {target} ({entries} entries, sha256 {digest[:16]}...)")


def commit_and_push(push):
    run(["git", "add", "-A"])
    if not run(["git", "status", "--porcelain"]).stdout.strip():
        log("git: no changes, nothing to commit")
        committed = False
    else:
        run(["git", "commit", "-q", "-m", f"auto-update: {datetime.date.today().isoformat()}"])
        log("git: committed " + run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip())
        committed = True
    if not push:
        return committed
    if "origin" not in run(["git", "remote"]).stdout.split():
        log("git: no 'origin' remote yet, push skipped")
        return committed
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    ahead = run(["git", "rev-list", "--count", f"origin/{branch}..HEAD"], check=False)
    if ahead.returncode == 0 and ahead.stdout.strip() == "0":
        log("git: origin already up to date")
        return committed
    run(["git", "push", "-u", "origin", branch])
    log(f"git: pushed {branch} to origin")
    return committed


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--outputs", type=Path, default=DEFAULT_OUTPUTS)
    parser.add_argument("--refresh-allowlists", action="store_true",
                        help="Also build a weekly China-direct allowlist preview (never applied automatically).")
    parser.add_argument("--allowlist-directory", type=Path, default=DEFAULT_ALLOWLIST_DIR)
    parser.add_argument("--no-sync", action="store_true")
    parser.add_argument("--no-push", action="store_true")
    parser.add_argument("--force-package", action="store_true")
    args = parser.parse_args(argv)
    committed = False
    try:
        if not args.no_sync:
            sync(args.source)
        privacy_gate()
        unit_tests()
        if args.refresh_allowlists:
            refresh_allowlists(args.allowlist_directory)
        committed = commit_and_push(push=not args.no_push)
        if committed or args.force_package:
            build_zip(args.outputs)
    except Exception as error:
        if not committed and run(["git", "rev-parse", "--verify", "HEAD"], check=False).returncode == 0:
            run(["git", "reset", "-q", "--hard", "HEAD"], check=False)
            run(["git", "clean", "-fdq"], check=False)
        log(f"FAILED: {error}")
        return 1
    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
