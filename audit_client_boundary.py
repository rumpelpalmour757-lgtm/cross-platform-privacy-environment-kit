#!/usr/bin/env python3
"""Read-only, redacted audit of host OS locale/timezone and local Claude client footprints."""

import argparse
from datetime import datetime
import json
import locale
import os
from pathlib import Path
import platform
import stat


# Client state files grow with per-project history; read them up to this size.
MAX_JSON_BYTES = 32 * 1024 * 1024
UNREAD_STATES = ("not_regular_file", "too_large", "invalid_json", "unreadable")
FLAG_ON_VALUES = ("1", "true", "yes")
FLAG_OFF_VALUES = ("0", "false", "no", "off")

CLI_ANTI_TELEMETRY_KEYS = (
    "DISABLE_TELEMETRY",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_ERROR_REPORTING",
    "DISABLE_AUTOUPDATER",
    "DISABLE_GROWTHBOOK",
)


def _utc_offset_hours(now_local):
    offset = now_local.utcoffset()
    if offset is None:
        return None
    return round(offset.total_seconds() / 3600.0, 2)


def _detect_timezone_name(sys_name, local_time):
    if sys_name == "Windows" and os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            ) as key:
                key_name, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
                if isinstance(key_name, str) and key_name.strip():
                    return key_name.strip()
        except OSError:
            pass
    tz = local_time.tzname() or "unknown"
    if "?" in tz:
        offset = _utc_offset_hours(local_time)
        if offset is not None:
            sign = "+" if offset >= 0 else ""
            return f"UTC{sign}{offset:g}"
    return tz


def _detect_locale():
    lang_tag = None
    try:
        loc = locale.getlocale()
        if loc and loc[0]:
            lang_tag = loc[0]
    except (OSError, ValueError):
        lang_tag = None
    if not lang_tag:
        for env_key in ("LC_ALL", "LC_MESSAGES", "LANG"):
            raw = (os.environ.get(env_key) or "").strip()
            if raw:
                lang_tag = raw.split(".", 1)[0]
                break
    return lang_tag or "unknown"


def _safe_exists(path):
    try:
        return os.path.lexists(path)
    except OSError:
        return False


def _has_msix_claude(local_appdata):
    if not local_appdata:
        return False
    packages = Path(local_appdata) / "Packages"
    try:
        if not packages.is_dir():
            return False
        return any(entry.name.startswith("Claude_") for entry in packages.iterdir())
    except OSError:
        return False


def _load_json_file(file_path):
    """Return (data, state) so callers keep "nothing configured" apart from "not checked".

    state is "absent" or "read", or one of the states in UNREAD_STATES for a file
    that exists but was not read: "not_regular_file" (symbolic link, directory, or
    other special entry), "too_large", "invalid_json", or "unreadable" (could not
    be opened or listed). An empty file is "read" with no data: it configures nothing,
    the same view claude_local_data.py takes when it checks a backup.
    """
    try:
        info = os.lstat(file_path)
    except (FileNotFoundError, NotADirectoryError):
        return None, "absent"
    except (OSError, ValueError):
        return None, "unreadable"
    if not stat.S_ISREG(info.st_mode):
        return None, "not_regular_file"
    if info.st_size > MAX_JSON_BYTES:
        return None, "too_large"
    try:
        raw = Path(file_path).read_text(encoding="utf-8-sig")
    except OSError:
        return None, "unreadable"
    except UnicodeError:
        return None, "invalid_json"
    if not raw.strip():
        return None, "read"
    try:
        return json.loads(raw), "read"
    except (ValueError, RecursionError):
        return None, "invalid_json"


def _settings_env(data):
    if isinstance(data, dict) and isinstance(data.get("env"), dict):
        return {str(key): str(val) for key, val in data["env"].items() if val is not None}
    return {}


def _mcp_entry_count(data):
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    return len(servers) if isinstance(servers, dict) else 0


def _project_scoped_mcp_count(data):
    # The CLI state file keeps per-project entries under projects.<path>.mcpServers.
    projects = data.get("projects") if isinstance(data, dict) else None
    if not isinstance(projects, dict):
        return 0
    return sum(_mcp_entry_count(entry) for entry in projects.values())


def _flag_enabled(value):
    return str(value or "").strip().lower() in FLAG_ON_VALUES


def _flag_undetermined(process_value, settings_value):
    """True when the values read do not settle whether a switch is on.

    That is a value outside the plain on/off spellings, or the process
    environment and settings.json disagreeing: which of the two the client
    applies last is not checked here.
    """
    states = set()
    for value in (process_value, settings_value):
        text = str(value or "").strip().lower()
        if not text:
            continue
        if text in FLAG_ON_VALUES:
            states.add(True)
        elif text in FLAG_OFF_VALUES:
            states.add(False)
        else:
            return True
    return len(states) > 1


def collect_boundary_audit(system=None, home=None, env=None, now_local=None, config_dir=None, project_dir=None):
    sys_name = system or platform.system()
    env_map = os.environ if env is None else env
    home_dir = Path(home) if home is not None else Path.home()
    local_time = now_local or datetime.now().astimezone()

    config_override = (env_map.get("CLAUDE_CONFIG_DIR") or "").strip()
    if config_dir is not None:
        cli_dir = Path(config_dir)
    elif config_override:
        cli_dir = Path(config_override)
    else:
        cli_dir = home_dir / ".claude"
    cli_state_files = [home_dir / ".claude.json"]
    if cli_dir != home_dir / ".claude" and cli_dir / ".claude.json" not in cli_state_files:
        # With a relocated configuration directory the state file may live inside it.
        cli_state_files.append(cli_dir / ".claude.json")
    cli_state_present = any(_safe_exists(path) for path in cli_state_files)
    settings_data, settings_state = _load_json_file(cli_dir / "settings.json")
    settings_env = _settings_env(settings_data)

    desktop_appdata_present = False
    desktop_msix_present = False
    desktop_config_dir = None
    if sys_name == "Windows":
        appdata = (env_map.get("APPDATA") or "").strip()
        local_appdata = (env_map.get("LOCALAPPDATA") or "").strip()
        if appdata:
            desktop_config_dir = Path(appdata) / "Claude"
            desktop_appdata_present = _safe_exists(desktop_config_dir)
        desktop_msix_present = _has_msix_claude(local_appdata)
    elif sys_name == "Darwin":
        desktop_config_dir = home_dir / "Library" / "Application Support" / "Claude"
        desktop_appdata_present = _safe_exists(desktop_config_dir)
    elif sys_name == "Linux":
        xdg_config = (env_map.get("XDG_CONFIG_HOME") or "").strip()
        base = Path(xdg_config) if xdg_config else (home_dir / ".config")
        desktop_config_dir = base / "Claude"
        desktop_appdata_present = _safe_exists(desktop_config_dir)

    desktop_mcp_count = 0
    desktop_mcp_unreadable = 0
    if desktop_config_dir is not None:
        data, state = _load_json_file(desktop_config_dir / "claude_desktop_config.json")
        desktop_mcp_count = _mcp_entry_count(data)
        desktop_mcp_unreadable = int(state in UNREAD_STATES)
    cli_mcp_count = _mcp_entry_count(settings_data)
    cli_mcp_unreadable = int(settings_state in UNREAD_STATES)
    for state_file in cli_state_files:
        data, state = _load_json_file(state_file)
        cli_mcp_count += _mcp_entry_count(data) + _project_scoped_mcp_count(data)
        cli_mcp_unreadable += int(state in UNREAD_STATES)
    if project_dir is not None:
        data, state = _load_json_file(Path(project_dir) / ".mcp.json")
        cli_mcp_count += _mcp_entry_count(data)
        cli_mcp_unreadable += int(state in UNREAD_STATES)
    local_mcp_bridges = {
        "claudeDesktopMcpConfigured": desktop_mcp_count > 0,
        "claudeDesktopMcpServerCount": desktop_mcp_count,
        "claudeDesktopMcpUnreadableConfigCount": desktop_mcp_unreadable,
        "claudeCliMcpConfigured": cli_mcp_count > 0,
        "claudeCliMcpServerCount": cli_mcp_count,
        "claudeCliMcpUnreadableConfigCount": cli_mcp_unreadable,
        "projectMcpConfigInspected": project_dir is not None,
    }

    env_flags = {
        "ANTHROPIC_BASE_URL_set": bool(
            (env_map.get("ANTHROPIC_BASE_URL") or settings_env.get("ANTHROPIC_BASE_URL") or "").strip()
        ),
        "CLAUDE_CONFIG_DIR_set": bool(config_override),
        "HTTP_PROXY_set": bool((env_map.get("HTTP_PROXY") or env_map.get("http_proxy") or "").strip()),
        "HTTPS_PROXY_set": bool((env_map.get("HTTPS_PROXY") or env_map.get("https_proxy") or "").strip()),
        "ALL_PROXY_set": bool((env_map.get("ALL_PROXY") or env_map.get("all_proxy") or "").strip()),
        "NO_PROXY_set": bool((env_map.get("NO_PROXY") or env_map.get("no_proxy") or "").strip()),
    }

    cli_anti_telemetry = {
        f"{key}_enabled": _flag_enabled(env_map.get(key) or settings_env.get(key))
        for key in CLI_ANTI_TELEMETRY_KEYS
    }
    cli_anti_telemetry_undetermined = [
        key for key in CLI_ANTI_TELEMETRY_KEYS
        if _flag_undetermined(env_map.get(key), settings_env.get(key))
    ]

    desktop_present = desktop_appdata_present or desktop_msix_present
    cli_present = _safe_exists(cli_dir) or cli_state_present
    warnings = []
    if desktop_present:
        warnings.append(
            "Native Claude Desktop data footprint detected. Desktop reads host OS locale/timezone directly "
            "and issues cold-start network requests (Sentry, first-party events, updates) even when logged out."
        )
    if cli_present:
        warnings.append(
            "Local Claude Code CLI footprint detected. CLI reads host OS timezone, sends non-disableable "
            "metadata.user_id on API requests, and reports custom ANTHROPIC_BASE_URL hostnames to GrowthBook."
        )
    if env_flags["ANTHROPIC_BASE_URL_set"]:
        warnings.append(
            "ANTHROPIC_BASE_URL is set in the environment. Keep host CLI sessions strictly separated from "
            "isolated web browser profiles."
        )
    if cli_present and not (
        cli_anti_telemetry["DISABLE_TELEMETRY_enabled"]
        and cli_anti_telemetry["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC_enabled"]
    ):
        warnings.append(
            "Claude CLI telemetry/non-essential traffic switches (DISABLE_TELEMETRY=1 and "
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1) are not both enabled; cold-start CLI runs "
            "may still contact api.anthropic.com:443 even when logged out or using a custom base URL."
        )
    if desktop_mcp_count > 0 or cli_mcp_count > 0:
        warnings.append(
            "Local MCP / host-tool bridge configuration detected. Local MCP servers run in the host OS "
            "context and may expose host clock, timezone, or local filesystem metadata into sessions; "
            "review enabled bridges when strict host isolation is required."
        )
    unreadable_configs = desktop_mcp_unreadable + cli_mcp_unreadable
    if unreadable_configs:
        warnings.append(
            f"{unreadable_configs} local client configuration file(s) exist but could not be read "
            "(symbolic link or other non-regular file, oversized, not valid JSON, or not readable); counts "
            "and switch states that depend on those files are incomplete."
        )

    return {
        "schemaVersion": 1,
        "platform": sys_name,
        "scope": (
            "Read-only redacted host boundary audit. Values, paths, usernames, and tokens are omitted; "
            "host timezone name, UTC offset, and locale are included."
        ),
        "hostEnvironment": {
            "timezoneName": _detect_timezone_name(sys_name, local_time),
            "utcOffsetHours": _utc_offset_hours(local_time),
            "detectedLocale": _detect_locale(),
        },
        "localClientFootprints": {
            "claudeCliConfigDirPresent": _safe_exists(cli_dir),
            "claudeCliStateFilePresent": cli_state_present,
            "claudeDesktopDataPresent": desktop_appdata_present,
            "claudeDesktopMsixPresent": desktop_msix_present,
        },
        "environmentVariableFlags": env_flags,
        "cliAntiTelemetryFlags": cli_anti_telemetry,
        "cliAntiTelemetryUndetermined": cli_anti_telemetry_undetermined,
        "cliSettingsReadState": settings_state,
        "localMcpBridges": local_mcp_bridges,
        "boundaryNotes": warnings or [
            "No native Claude Desktop or CLI data footprints were observed in default host locations."
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", type=Path, help="Override the Claude CLI configuration directory.")
    parser.add_argument("--project-dir", type=Path, help="Also count MCP entries in this project's .mcp.json.")
    args = parser.parse_args(argv)
    result = collect_boundary_audit(config_dir=args.config_dir, project_dir=args.project_dir)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
