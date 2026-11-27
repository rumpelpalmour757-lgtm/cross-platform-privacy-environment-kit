"""Offline inventory and local snapshots of selected Claude Code work files."""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from uuid import uuid4

sys.dont_write_bytecode = True

from config_snapshot import (
    SnapshotError, check_ancestors, checked_stat, copy_tree, describe_names, ensure_distinct, inventory,
    local_path, path_is_within, paths_overlap, recorded_path, restrict_private_permissions, safe_rmtree,
    storage_problem, tolerate_unencodable_output,
)


CONFIG_NAMES = {
    "projects": "sessions_and_project_data",
    "history.jsonl": "history",
    "CLAUDE.md": "instructions",
    "CLAUDE.local.md": "instructions",
    "skills": "skills",
    "hooks": "hooks",
    "commands": "commands",
    "agents": "agents",
    "agent-memory": "memory",
    "rules": "rules",
    "settings.json": "settings",
    "settings.local.json": "settings",
    ".mcp.json": "mcp",
}
PROJECT_NAMES = {
    "CLAUDE.md": "instructions",
    "CLAUDE.local.md": "instructions",
    ".mcp.json": "mcp",
}
DEDICATED_NAMES = {
    ".claude.json", ".claude.json.backup", ".credentials.json", "credentials.json",
    "oauth_tokens.json", ".git", "keyring", "keychains",
    ".npmrc", ".netrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa",
    "secrets.json", "token.json", "auth.json",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdbx")
SECRET_CHECKED_JSON_NAMES = {"settings.json", "settings.local.json", ".mcp.json"}
# Matched against a key name with separators and case removed (api_key, apiKey, API-KEY).
SECRET_KEY_FRAGMENTS = (
    "apikey", "authtoken", "accesstoken", "refreshtoken", "privatekey", "secret",
    "password", "passwd", "passphrase", "authorization", "bearer",
)
# Whole words that also mark a secret under env or headers, in URL queries,
# command-line flags and NAME=value assignments.
SECRET_KEY_WORDS = {
    "token", "key", "apikey", "secret", "secrets", "password", "pass", "pwd", "credential", "credentials",
    "pat", "cookie",
}
# A key named after one of these words holds a secret wherever it appears (auth.token, apiToken).
SECRET_LAST_WORDS = {"token"}
# The same, for the direct children of env and headers (X-Auth) and for flags and assignments.
BROAD_SECRET_LAST_WORDS = {"auth"}
# Keys meant to be shared, such as a public or publishable key.
PUBLIC_KEY_WORDS = {"public", "publishable"}
# A trailing word like these names a location, helper, timing setting or another name, not the secret itself.
NON_SECRET_LAST_WORDS = {
    "dir", "directory", "path", "file", "helper", "command", "cmd", "url", "uri", "ttl", "ms", "timeout",
    "env", "name", "id", "limit", "max", "min", "count", "size", "length", "domain",
}
# Known settings whose values are helper commands or file paths. Their values are still
# searched for secret-shaped text.
NON_SECRET_KEYS = {
    "apikeyhelper", "awsauthrefresh", "awscredentialexport", "otelheadershelper",
    "claude_code_api_key_helper_ttl_ms", "claude_code_client_key", "google_application_credentials",
}
SECRET_VALUE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})"
    r"|(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})"
    r"|\bBearer\s+(?=[^\s'\"]*[0-9])[^\s'\"]{8,}"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
# References, not values: $env:VAR and ${env:VAR} (PowerShell), %VAR% (cmd.exe), ${VAR} and $VAR.
# ${VAR:-default} keeps its literal default.
PLACEHOLDER_PATTERN = re.compile(
    r"\$\{?(?i:env):[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\$\{[A-Za-z_][A-Za-z0-9_]*(?::-(?P<default>[^{}]*))?\}|\$[A-Z_][A-Z0-9_]*\b"
)
# Inside a command line the shell also expands lower-case names such as $tok.
SHELL_REFERENCE_PATTERN = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
AUTH_SCHEME_PATTERN = re.compile(r"^(?:bearer|basic|token)\b\s*", re.IGNORECASE)
NON_SECRET_WORDS = {"true", "false", "yes", "no", "on", "off", "0", "1"}
# A file path after --key or --cert names where the secret is kept, not the secret itself.
PATH_LIKE_PATTERN = re.compile(r"^(?:/|\.{1,2}[\\/]|~[\\/]|[A-Za-z]:[\\/])|\.(?:pem|key|crt|p12|pfx)$", re.IGNORECASE)
URL_PASSWORD_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#@:]*:[^\s/?#@]+@")
ASSIGNMENT_PATTERN = re.compile(r"(?:^|[\s?&#;'\"(])-{0,2}([A-Za-z_][A-Za-z0-9_.-]*)=([^\s&#'\"]*)")
HEADER_PATTERN = re.compile(r"(?:^|[\s'\"])([A-Za-z][A-Za-z0-9_-]*)\s*:\s*([^'\"\r\n]*)")
# Headers that carry credentials whatever their value looks like (Cookie: a=1; sid=...).
AUTH_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key", "x-auth-token",
    "x-access-token", "x-token", "private-token", "x-goog-api-key",
}
# Command-line options that take a "Name: value" header.
HEADER_FLAGS = ("-h", "--header", "-header", "-headers")
# The same options written with "=" and no space: --header=Name: value, -H=Name: value.
HEADER_FLAG_EQUALS = re.compile(r"(?:^|(?<=[\s'\"]))(-h|--header|-header|-headers)=", re.IGNORECASE)
FLAG_PATTERN = re.compile(r"^-{1,2}([A-Za-z][A-Za-z0-9_-]*)$")
MAX_LISTED_FINDINGS = 10
# Windows refuses longer paths unless long paths are enabled (folders: 248 characters).
WINDOWS_MAX_PATH = 260
FORMAT_VERSION = 2
MANIFEST_NAME = "manifest.json"
PAYLOAD_NAME = "work"


@dataclass(frozen=True)
class WorkFile:
    source: Path
    relative: Path
    category: str
    identity: tuple
    posix_mode: int | None


def _configured_env_dir():
    value = os.environ.get("CLAUDE_CONFIG_DIR")
    # Whitespace-only does not specify a directory. Preserve nonblank paths verbatim.
    return value if value and value.strip() else None


def selected_config_path(value=None):
    return recorded_path(value or _configured_env_dir() or Path.home() / ".claude")


def selected_config(value=None):
    return local_path(selected_config_path(value))


def identity_of(info):
    # Mask st_mode to file type only: on Windows, lstat() sets execute bits for
    # .bat/.cmd/.exe/.com while fstat() does not, which caused false mismatches.
    return (stat.S_IFMT(info.st_mode), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def is_sensitive_name(name):
    folded = name.casefold()
    return (
        folded in DEDICATED_NAMES
        or folded == ".env"
        or folded.startswith(".env.")
        or folded.endswith(SENSITIVE_SUFFIXES)
    )


class _JsonPairs(list):
    """A JSON object as its (key, value) pairs, keeping duplicate keys that json.loads would drop."""


def _key_words(name):
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", name)
    return [word for word in re.split(r"[^a-z0-9]+", spaced.casefold()) if word]


def _secret_named(name, broad=False):
    if name.casefold() in NON_SECRET_KEYS:
        return False
    words = _key_words(name)
    if not words or words[-1] in NON_SECRET_LAST_WORDS or PUBLIC_KEY_WORDS.intersection(words):
        return False
    joined = "".join(words)
    if any(fragment in joined for fragment in SECRET_KEY_FRAGMENTS) or words[-1] in SECRET_LAST_WORDS:
        return True
    return broad and (words[-1] in BROAD_SECRET_LAST_WORDS or any(word in SECRET_KEY_WORDS for word in words))


def _literal_text(text):
    for _ in range(5):  # Nested ${A:-${B}} defaults unwrap one level per pass.
        expanded = PLACEHOLDER_PATTERN.sub(lambda match: match.group("default") or "", text)
        if expanded == text:
            break
        text = expanded
    return text


def _plain_value(text, in_command=False):
    """The value with references, quotes and an auth scheme such as "Bearer" taken off."""
    text = _literal_text(text)
    if in_command:
        text = SHELL_REFERENCE_PATTERN.sub("", text)
    return AUTH_SCHEME_PATTERN.sub("", text.strip().strip("'\"")).strip()


def _is_literal_secret_value(text, in_command=False):
    value = _plain_value(text, in_command)
    if not value or value.casefold() in NON_SECRET_WORDS:
        return False
    if in_command and not any(character.isalnum() for character in value):
        return False  # Wildcards and punctuation, such as the "*)" of a permission rule Bash(gh auth token:*).
    if in_command and value.startswith(("|", "\\", "(", "[")):
        return False  # A search pattern, such as grep -E 'token=|password=' or rg 'token=\w+'.
    return not value.startswith(("$(", "`"))  # Command substitution fetches the value at run time.


def _header_has_secret(literal, match):
    name, value = match.group(1), match.group(2)
    if not _secret_named(name, broad=True) or not _is_literal_secret_value(value, in_command=True):
        return False
    if name.casefold() in AUTH_HEADER_NAMES or len(_plain_value(value, in_command=True).split()) == 1:
        return True
    # Several words after "Name:" are prose, as in echo 'Password: not stored here', unless
    # the text is the value of a header option such as curl -H.
    before = literal[:match.start(1)].rstrip(" \t'\"=").split()
    return bool(before) and before[-1].casefold() in HEADER_FLAGS


def _string_has_secret(text):
    literal = _literal_text(text)
    if SECRET_VALUE_PATTERN.search(literal) or URL_PASSWORD_PATTERN.search(literal):
        return True
    for match in ASSIGNMENT_PATTERN.finditer(literal):
        if _secret_named(match.group(1), broad=True) and _is_literal_secret_value(match.group(2), in_command=True):
            return True
    # Read --header=Name: value as --header Name: value. "=" becomes a space, so offsets stay the same.
    headers = HEADER_FLAG_EQUALS.sub(lambda match: match.group(1) + " ", literal)
    return any(_header_has_secret(headers, match) for match in HEADER_PATTERN.finditer(headers))


def _find_inline_secrets(document):
    """Return the key paths of likely inline secrets. Values are never returned."""
    findings = []
    stack = [(document, (), False)]
    while stack:
        node, path, broad = stack.pop()
        children = []
        if isinstance(node, _JsonPairs):
            for key, value in node:
                key_path = path + (key,)
                if SECRET_VALUE_PATTERN.search(key):
                    findings.append(key_path)
                elif isinstance(value, str):
                    if _string_has_secret(value) or (
                        _secret_named(key, broad) and _is_literal_secret_value(value)
                    ):
                        findings.append(key_path)
                children.append((value, key_path, key.casefold() in {"env", "headers"}))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                item_path = path + (index,)
                if isinstance(item, str):
                    flag = FLAG_PATTERN.match(item)
                    following = node[index + 1] if index + 1 < len(node) else None
                    previous = node[index - 1] if index else None
                    # An item right after -H or --header is that option's "Name: value", so it is
                    # checked as a header value even when the value has several words.
                    after_header_flag = isinstance(previous, str) and previous.casefold() in HEADER_FLAGS
                    if _string_has_secret(item) or (after_header_flag and _string_has_secret(f"{previous} {item}")):
                        findings.append(item_path)
                    elif (
                        flag and _secret_named(flag.group(1), broad=True) and isinstance(following, str)
                        and not following.startswith("-") and not PATH_LIKE_PATTERN.search(following)
                        and _is_literal_secret_value(following)
                    ):
                        findings.append(path + (index + 1,))
                children.append((item, item_path, False))
        elif isinstance(node, str) and _string_has_secret(node):
            findings.append(path)
        stack.extend(child for child in reversed(children) if isinstance(child[0], (_JsonPairs, list)))
    unique = []
    for item in findings:
        if item not in unique:
            unique.append(item)
    return unique


def _format_key_path(path):
    text = ""
    for part in path:
        if isinstance(part, int):
            text += f"[{part}]"
            continue
        shown = "<redacted>" if SECRET_VALUE_PATTERN.search(part) else part
        if len(shown) > 60:
            shown = shown[:57] + "..."
        if not shown.isprintable():
            shown = repr(shown)
        text += ("." if text else "") + shown
    return text or "(top level)"


def _inline_secret_findings(copied_path, original_name, label):
    """Name where a checked file may hold an inline secret, or why it could not be checked."""
    if original_name.casefold() not in SECRET_CHECKED_JSON_NAMES:
        return []
    try:
        text = copied_path.read_text(encoding="utf-8-sig")
        if not text.strip():
            return []  # An empty file holds nothing to leak.
        document = json.loads(text, object_pairs_hook=_JsonPairs)
    except UnicodeError:
        return [f"{label} (not UTF-8 text, so it could not be checked)"]
    except (ValueError, RecursionError):
        return [f"{label} (not strict JSON, e.g. comments or trailing commas, so it could not be checked)"]
    return [f"{label}: {_format_key_path(path)}" for path in _find_inline_secrets(document)]


def _describe_findings(findings):
    text = "; ".join(findings[:MAX_LISTED_FINDINGS])
    if len(findings) > MAX_LISTED_FINDINGS:
        text += f"; and {len(findings) - MAX_LISTED_FINDINGS} more"
    return text


def scan_work(config, project=None):
    files = []
    directories = []
    skipped = {
        "unsafe_or_unavailable": 0, "excluded_secret_entries": 0, "unsafe_or_unavailable_by_area": {},
    }
    roots = {"user_config_present": False, "project_selected": project is not None}

    def count_unsafe(area):
        skipped["unsafe_or_unavailable"] += 1
        areas = skipped["unsafe_or_unavailable_by_area"]
        areas[area] = areas.get(area, 0) + 1

    def visit(source, relative, category):
        if is_sensitive_name(source.name):
            skipped["excluded_secret_entries"] += 1
            return
        try:
            info = checked_stat(source)
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
                for entry in sorted(source.iterdir(), key=lambda item: item.name):
                    visit(entry, relative / entry.name, category)
            elif stat.S_ISREG(info.st_mode):
                # Strip group/world write bits (0o022) when recording POSIX permissions.
                mode = (info.st_mode & 0o755) if os.name == "posix" else None
                files.append(WorkFile(source, relative, category, identity_of(info), mode))
            else:
                count_unsafe(category)
        except (OSError, SnapshotError, RecursionError):  # RecursionError: folders nested too deeply.
            count_unsafe(category)

    def selected_names(directory, prefix, names, area):
        case_insensitive = os.name == "nt" or sys.platform == "darwin"
        if case_insensitive:
            names = {name.casefold(): category for name, category in names.items()}
        try:
            check_ancestors(directory)
            for entry in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
                if is_sensitive_name(entry.name):
                    skipped["excluded_secret_entries"] += 1
                    continue
                match_name = entry.name.casefold() if case_insensitive else entry.name
                if match_name in names:
                    visit(entry, prefix / entry.name, names[match_name])
            return True
        except FileNotFoundError:
            return False
        except (OSError, SnapshotError):
            count_unsafe(area)
            return False

    roots["user_config_present"] = selected_names(
        config, Path("user-config"), CONFIG_NAMES, "user_config_root",
    )
    if project is not None:
        active_project_config = project / ".claude"
        if paths_overlap(config, project) or paths_overlap(config, active_project_config):
            raise SnapshotError("Select non-overlapping user and project scopes.")
        roots["project_present"] = selected_names(project, Path("project"), PROJECT_NAMES, "project_root")
        roots["project_config_present"] = selected_names(
            active_project_config, Path("project") / ".claude", CONFIG_NAMES, "project_config_root",
        )
    return files, directories, skipped, roots


def audit(config, project=None):
    # The inventory only reads metadata, so it also runs on network or synced storage and says so.
    config = recorded_path(config)
    project = recorded_path(project) if project is not None else None
    on_unsupported_storage = any(
        storage_problem(path) is not None for path in (config, project) if path is not None
    )
    files, directories, skipped, roots = scan_work(config, project)
    categories = {}
    for entry in files:
        count = categories.setdefault(entry.category, {"files": 0, "bytes": 0})
        count["files"] += 1
        count["bytes"] += entry.identity[3]
    return {
        **roots,
        **skipped,
        "files": len(files),
        "directories": len(directories),
        "bytes": sum(entry.identity[3] for entry in files),
        "categories": categories,
        "mixed_account_state_backed_up": False,
        "contents_read": False,
        "network_or_synced_storage": on_unsupported_storage,
    }


def enforce_unchanged(entry):
    check_ancestors(entry.source.parent)
    if identity_of(checked_stat(entry.source)) != entry.identity:
        raise SnapshotError("A selected source changed. Close its writer and retry.")


def copy_file(entry, destination):
    enforce_unchanged(entry)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    open_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(entry.source, open_flags)
    try:
        opened_stat = os.fstat(fd)
        if (
            not stat.S_ISREG(opened_stat.st_mode)
            or getattr(opened_stat, "st_nlink", 1) > 1
            or identity_of(opened_stat) != entry.identity
        ):
            raise SnapshotError("A selected source changed before it was read.")
        with os.fdopen(fd, "rb") as source, destination.open("xb") as target:
            fd = -1
            if os.name == "posix":
                os.fchmod(target.fileno(), 0o600)
            while block := source.read(1024 * 1024):
                digest.update(block)
                target.write(block)
                size += len(block)
            if identity_of(os.fstat(source.fileno())) != entry.identity or size != entry.identity[3]:
                raise SnapshotError("A selected source changed during copying.")
    finally:
        if fd >= 0:
            os.close(fd)
    enforce_unchanged(entry)
    return {"size": size, "sha256": digest.hexdigest()}


def publication_name(prefix):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}-{timestamp}-{uuid4().hex}"


def staging_folder(destination, name, inner=None):
    """Create the private folder a snapshot is built in before it is published as ``name``.

    The folder (or ``inner`` inside it) is exactly as long a path as the published one, so
    every file that was written and verified while staging can still be opened after the
    rename. Windows refuses paths over 260 characters unless long paths are enabled; a
    shorter staging name let a snapshot verify there and fail to open once published.
    """
    reserved = len(name) - (len(inner) + 1 if inner else 0)
    stage = destination / ("." + name[:reserved - 1])
    stage.mkdir(mode=0o700)
    return stage


def publish(stage, destination, name):
    target = destination / name
    if os.path.lexists(target):
        raise SnapshotError("A publication path is already present.")
    stage.rename(target)
    return target


def permissions_digest(modes):
    metadata = json.dumps(modes, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(metadata.encode("ascii")).hexdigest()


def read_verified_snapshot(snapshot):
    snapshot = local_path(snapshot)
    check_ancestors(snapshot)
    present_entries = {entry.name for entry in snapshot.iterdir()}
    if not present_entries <= {MANIFEST_NAME, PAYLOAD_NAME}:
        unexpected = describe_names(present_entries - {MANIFEST_NAME, PAYLOAD_NAME})
        raise SnapshotError(
            f"Snapshot directory contains unexpected files: {unexpected}. Remove them and retry."
        )
    manifest = snapshot / MANIFEST_NAME
    info = checked_stat(manifest)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
        raise SnapshotError("Invalid backup manifest.")
    try:
        expected = json.loads(manifest.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SnapshotError("Invalid backup manifest.") from exc
    if (not isinstance(expected, dict) or type(expected.get("format")) is not int
            or expected["format"] not in (1, FORMAT_VERSION)):
        raise SnapshotError("Unsupported backup format.")
    actual = inventory(snapshot / PAYLOAD_NAME)
    if not actual["files"] or actual != expected.get("inventory"):
        raise SnapshotError("Backup contents do not match the manifest.")
    if expected["format"] == 1:
        return actual, None  # These snapshots never recorded the source permissions.
    if "posix_modes" not in expected:
        raise SnapshotError("Backup file permissions are missing.")
    modes = expected["posix_modes"]
    if modes is not None and (
        not isinstance(modes, dict) or modes.keys() != actual["files"].keys()
        or any(
            type(mode) is not int or not 0 <= mode <= 0o777 or (mode & 0o022) != 0
            for mode in modes.values()
        )
    ):
        raise SnapshotError("Invalid or overly permissive backup file permissions.")
    if permissions_digest(modes) != expected.get("posix_modes_sha256"):
        raise SnapshotError("Backup file permissions do not match their checksum.")
    return actual, modes


def verify(snapshot):
    return read_verified_snapshot(snapshot)[0]


def require_destination(destination):
    try:
        check_ancestors(destination)
    except FileNotFoundError as exc:
        raise SnapshotError(
            "The destination directory does not exist. Create a local folder that only you can access first."
        ) from exc


def backup(config, project, destination, *, require_config=True, allow_inline_secrets=False, report=None):
    """Publish a verified snapshot. A dict passed as report receives what was left out or let through."""
    config = local_path(config)
    project = local_path(project) if project is not None else None
    destination = local_path(destination)
    require_destination(destination)
    ensure_distinct(config, destination)
    if project is not None:
        ensure_distinct(project, destination)
    selection = scan_work(config, project)
    files, directories, skipped, roots = selection
    unsafe = skipped["unsafe_or_unavailable"]
    if unsafe:
        areas = ", ".join(sorted(skipped["unsafe_or_unavailable_by_area"]))
        raise SnapshotError(
            f"Audit found {unsafe} {'entry that is' if unsafe == 1 else 'entries that are'} a link, "
            f"hardlink, special file or unreadable (in: {areas}). Links are never followed; replace "
            "them with the real files or back up their targets separately."
        )
    if require_config and not roots["user_config_present"]:
        raise SnapshotError("The selected user configuration directory does not exist.")
    if project is not None and not roots["project_present"]:
        raise SnapshotError("The selected project directory does not exist.")
    if not files:
        raise SnapshotError("No selected work files were found.")
    final_name = publication_name("claude-work")
    stage = staging_folder(destination, final_name)
    try:
        restrict_private_permissions(stage, is_dir=True)
        payload = stage / PAYLOAD_NAME
        payload.mkdir(mode=0o700)
        for relative in directories:
            (payload / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        expected_files = {}
        findings = []
        for entry in files:
            copied_dest = payload / entry.relative
            expected_files[entry.relative.as_posix()] = copy_file(entry, copied_dest)
            # Inspect the copied bytes, which are exactly what the snapshot would keep.
            label = entry.relative.as_posix()
            findings.extend(_inline_secret_findings(copied_dest, entry.source.name, label))
        if findings and not allow_inline_secrets:
            raise SnapshotError(
                f"Inline API keys or auth tokens were detected, or a file could not be checked: "
                f"{_describe_findings(findings)}. Move secrets to environment variables/keychain "
                "(placeholders such as ${VAR} are fine), or pass --allow-inline-secrets."
            )
        if selection != scan_work(config, project):
            raise SnapshotError("The selected source changed during backup.")
        checked = inventory(payload)
        if expected_files != checked["files"]:
            raise SnapshotError("Backup validation failed.")
        modes = None
        if os.name == "posix":
            modes = {entry.relative.as_posix(): entry.posix_mode for entry in files}
        manifest = {
            "format": FORMAT_VERSION, "inventory": checked, "scopes": roots,
            "posix_modes": modes, "posix_modes_sha256": permissions_digest(modes),
            # Readers ignore unknown keys, so snapshots without this count stay valid.
            "excluded_secret_entries": skipped["excluded_secret_entries"],
        }
        (stage / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        verify(stage)
        published = publish(stage, destination, final_name)
        if report is not None:
            report["excluded_secret_entries"] = skipped["excluded_secret_entries"]
            report["allowed_inline_secret_findings"] = findings
        return published
    finally:
        safe_rmtree(stage)


def recover(snapshot, destination):
    snapshot, destination = local_path(snapshot), local_path(destination)
    require_destination(destination)
    # Same rule as config_snapshot recover: the folder that holds the snapshot is fine.
    if path_is_within(destination, snapshot):
        raise SnapshotError("Choose a recovery directory outside the snapshot.")
    expected, modes = read_verified_snapshot(snapshot)
    final_name = publication_name("claude-recovery")
    staging_root = staging_folder(destination, final_name, inner="recovery")
    try:
        restrict_private_permissions(staging_root, is_dir=True)
        recovery = staging_root / "recovery"
        copy_tree(snapshot / PAYLOAD_NAME, recovery, expected, preserve_metadata=False)
        if os.name == "posix":
            for name in expected["files"]:
                target = recovery / name
                mode = (modes[name] & 0o755) if modes is not None else 0o600
                target.chmod(mode)
                if stat.S_IMODE(checked_stat(target).st_mode) != mode:
                    raise SnapshotError("The recovery filesystem did not preserve file permissions.")
        return publish(recovery, destination, final_name)
    finally:
        safe_rmtree(staging_root)


def _is_windows():
    return os.name == "nt"


def _long_path_hint(error):
    """Explain a Windows error on a path near the length limit. The path itself is not shown."""
    if not _is_windows() or not isinstance(error, OSError):
        return ""
    lengths = [len(os.fspath(name)) for name in (error.filename, error.filename2)
               if isinstance(name, (str, bytes, os.PathLike))]
    if not lengths or max(lengths) < WINDOWS_MAX_PATH - 12:
        return ""
    return (
        f" A path involved is {max(lengths)} characters long; Windows refuses paths over "
        f"{WINDOWS_MAX_PATH} characters (folders over {WINDOWS_MAX_PATH - 12}) unless long paths are "
        "enabled. Choose a shorter destination folder, or enable long paths (the python.org "
        "installer's 'Disable path length limit', or LongPathsEnabled = 1)."
    )


def main(argv=None):
    tolerate_unencodable_output()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for operation in ("audit", "backup"):
        entry = commands.add_parser(operation)
        entry.add_argument("--config-dir", help="Defaults to CLAUDE_CONFIG_DIR or ~/.claude.")
        entry.add_argument("--project-dir", help="Optionally select one project for local settings.")
        if operation == "backup":
            entry.add_argument("--destination", required=True, help="Existing private local directory.")
            entry.add_argument(
                "--allow-inline-secrets", action="store_true",
                help="Back up settings/.mcp.json even if likely inline secrets are found or a file "
                     "could not be checked. What was let through is still listed.",
            )
    for operation in ("verify", "recover"):
        entry = commands.add_parser(operation)
        entry.add_argument("snapshot")
        if operation == "recover":
            entry.add_argument("--destination", required=True, help="Existing private local directory.")
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            config = selected_config_path(args.config_dir)
            project = recorded_path(args.project_dir) if args.project_dir else None
            print(json.dumps(audit(config, project), sort_keys=True, indent=2))
        elif args.command == "backup":
            config = selected_config(args.config_dir)
            project = local_path(args.project_dir) if args.project_dir else None
            require_config = args.config_dir is not None or _configured_env_dir() is not None
            report = {}
            path = backup(
                config, project, args.destination,
                require_config=require_config,
                allow_inline_secrets=args.allow_inline_secrets,
                report=report,
            )
            print(f"Verified local backup: {path}")
            left_out = report["excluded_secret_entries"]
            if left_out:
                print(
                    f"Left out by name: {left_out} secret-like {'entry' if left_out == 1 else 'entries'} "
                    "(.env*, credential and key files, .git); not in this backup."
                )
            if report["allowed_inline_secret_findings"]:
                print(
                    "Warning: --allow-inline-secrets kept these in the backup: "
                    f"{_describe_findings(report['allowed_inline_secret_findings'])}",
                    file=sys.stderr,
                )
        else:
            snapshot = local_path(args.snapshot)
            if args.command == "verify":
                checked = verify(snapshot)
                print(f"Verified local backup ({len(checked['files'])} work files).")
            else:
                path = recover(snapshot, local_path(args.destination))
                print(f"Verified recovery copy: {path}")
    except SnapshotError as error:
        print(f"Claude work operation stopped: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        # RuntimeError covers RecursionError and an unresolvable "~user" path.
        print(f"Claude work operation stopped ({type(error).__name__}).{_long_path_hint(error)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
