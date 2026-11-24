import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pwn_broker.paths import AppPaths
from pwn_broker.store import write_toml

DEFAULT_OPT = Path("/opt/pwn-broker")
DEFAULT_TOOLS_INDEX = (
    "https://github.com/Real-Fruit-Snacks/pwn-shop/releases/download/index/index.toml"
)


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    home: Path | None = None
    copy_to: Path | None = None
    default_platform: str = "htb"
    terminal: str = "x-terminal-emulator"
    check_updates: bool = True
    tools_index: str | None = None
    # each scan mode's nmap options; None is the built-in default
    scan_quick: str | None = None
    scan_full: str | None = None
    scan_udp: str | None = None
    # whether a new box gets the playbooks, and the report tool; None leaves it to the answer
    # saved in state.toml
    playbooks: bool | None = None
    report: bool | None = None


@dataclass(frozen=True)
class State:
    last_platform: str | None = None
    last_vpn_file: str | None = None
    # the answers to the questions the first new box asks; None until each is answered
    new_box_playbooks: bool | None = None
    new_box_report: bool | None = None


def _expand(text: str, home_dir: Path) -> Path:
    if text == "~":
        return home_dir
    if text.startswith("~/"):
        return home_dir / text[2:]
    return Path(text)


def _whole(path: Path, label: str) -> Path:
    # the note window, serve, scan and record each run from a folder of their own, so a relative
    # path would name a different place in each
    if not (path.as_posix().startswith("/") or path.is_absolute()):
        raise ConfigError(f"{label} must be a whole path, such as ~/pwn-broker, not {str(path)!r}")
    return path


def _index_setting(text: str | None, home_dir: Path) -> str | None:
    if not text:
        return None
    if text.startswith(("http://", "https://")):
        return text
    return str(_expand(text, home_dir))


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc


def _typed(data: dict, key: str, kind: type, path: Path):
    value = data.get(key)
    if value is not None and not isinstance(value, kind):
        raise ConfigError(f"{path}: {key} must be a {kind.__name__}")
    return value


def load(env: Mapping[str, str], home_dir: Path) -> tuple[AppPaths, Settings]:
    # an empty one is "not set", as PWN_BROKER_HOME is, never the current folder
    opt = _whole(Path(env["PWN_BROKER_OPT"]), "PWN_BROKER_OPT") if env.get("PWN_BROKER_OPT") else DEFAULT_OPT
    config_file = opt / "config.toml"
    data = _read_toml(config_file)

    home_text = _typed(data, "home", str, config_file)
    copy_text = _typed(data, "copy_to", str, config_file)
    defaults = Settings()
    settings = Settings(
        # an empty string is "not set", never the current folder
        home=_whole(_expand(home_text, home_dir), f"{config_file}: home") if home_text else None,
        copy_to=_whole(_expand(copy_text, home_dir), f"{config_file}: copy_to") if copy_text else None,
        default_platform=_typed(data, "default_platform", str, config_file)
        or defaults.default_platform,
        terminal=_typed(data, "terminal", str, config_file) or defaults.terminal,
        check_updates=(
            defaults.check_updates
            if "check_updates" not in data
            else _typed(data, "check_updates", bool, config_file)
        ),
        tools_index=_index_setting(_typed(data, "tools_index", str, config_file), home_dir),
        scan_quick=_typed(data, "scan_quick", str, config_file) or None,
        scan_full=_typed(data, "scan_full", str, config_file) or None,
        scan_udp=_typed(data, "scan_udp", str, config_file) or None,
        playbooks=_typed(data, "playbooks", bool, config_file),
        report=_typed(data, "report", bool, config_file),
    )

    if settings.home is not None:
        home = settings.home
    elif env.get("PWN_BROKER_HOME"):
        home = _whole(Path(env["PWN_BROKER_HOME"]), "PWN_BROKER_HOME")
    else:
        home = home_dir / "pwn-broker"
    return AppPaths(opt=opt, home=home), settings


def load_state(state_file: Path) -> State:
    try:
        data = tomllib.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return State()
    last = data.get("last_platform")
    vpn = data.get("last_vpn_file")
    playbooks = data.get("new_box_playbooks")
    report = data.get("new_box_report")
    return State(
        last_platform=last if isinstance(last, str) else None,
        last_vpn_file=vpn if isinstance(vpn, str) else None,
        new_box_playbooks=playbooks if isinstance(playbooks, bool) else None,
        new_box_report=report if isinstance(report, bool) else None,
    )


def save_state(state_file: Path, state: State) -> None:
    data: dict = {"schema": 1}
    if state.last_platform is not None:
        data["last_platform"] = state.last_platform
    if state.last_vpn_file is not None:
        data["last_vpn_file"] = state.last_vpn_file
    if state.new_box_playbooks is not None:
        data["new_box_playbooks"] = state.new_box_playbooks
    if state.new_box_report is not None:
        data["new_box_report"] = state.new_box_report
    write_toml(state_file, data)


def platform_default(state: State, settings: Settings) -> str:
    return state.last_platform or settings.default_platform
