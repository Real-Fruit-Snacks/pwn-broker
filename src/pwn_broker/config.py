import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pwn_broker.paths import AppPaths
from pwn_broker.store import write_toml

DEFAULT_OPT = Path("/opt/pwn-broker")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    home: Path | None = None
    copy_to: Path | None = None
    default_platform: str = "htb"
    terminal: str = "x-terminal-emulator"
    check_updates: bool = True


@dataclass(frozen=True)
class State:
    last_platform: str | None = None


def _expand(text: str, home_dir: Path) -> Path:
    if text == "~":
        return home_dir
    if text.startswith("~/"):
        return home_dir / text[2:]
    return Path(text)


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
    opt = Path(env["PWN_BROKER_OPT"]) if "PWN_BROKER_OPT" in env else DEFAULT_OPT
    config_file = opt / "config.toml"
    data = _read_toml(config_file)

    home_text = _typed(data, "home", str, config_file)
    copy_text = _typed(data, "copy_to", str, config_file)
    defaults = Settings()
    settings = Settings(
        # an empty string is "not set", never the current folder
        home=_expand(home_text, home_dir) if home_text else None,
        copy_to=_expand(copy_text, home_dir) if copy_text else None,
        default_platform=_typed(data, "default_platform", str, config_file)
        or defaults.default_platform,
        terminal=_typed(data, "terminal", str, config_file) or defaults.terminal,
        check_updates=(
            defaults.check_updates
            if "check_updates" not in data
            else _typed(data, "check_updates", bool, config_file)
        ),
    )

    if settings.home is not None:
        home = settings.home
    elif env.get("PWN_BROKER_HOME"):
        home = Path(env["PWN_BROKER_HOME"])
    else:
        home = home_dir / "pwn-broker"
    return AppPaths(opt=opt, home=home), settings


def load_state(state_file: Path) -> State:
    try:
        data = tomllib.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return State()
    last = data.get("last_platform")
    return State(last_platform=last if isinstance(last, str) else None)


def save_state(state_file: Path, state: State) -> None:
    data: dict = {"schema": 1}
    if state.last_platform is not None:
        data["last_platform"] = state.last_platform
    write_toml(state_file, data)


def platform_default(state: State, settings: Settings) -> str:
    return state.last_platform or settings.default_platform
